package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/regretable"
	uA "github.com/mssola/user_agent"
)

var (
	sessions = newSessionMap()
)

type stringChecker struct {
	pattern string
	reader  io.ReadCloser
}

func newStringChecker(s string, r io.ReadCloser) *stringChecker {
	return &stringChecker{s, r}
}

func (s *stringChecker) Read(p []byte) (n int, err error) {
	n, err = s.reader.Read(p)

	if bytes.Contains(p[:n], []byte(s.pattern)) {
		log.Println("Pattern -> (", s.pattern, ") found")
	}

	return
}

func (s *stringChecker) Close() error {
	return s.reader.Close()
}

type sshConnectionPackets struct {
	clientPackets []int64
	serverPackets []int64
}

func newSshConnectionChecker() *sshConnectionPackets {
	var ps sshConnectionPackets
	ps.clientPackets = []int64{21, 1392, 48, 16}
	ps.serverPackets = []int64{21, 1080, 452}

	return &ps
}

func (s *sshConnectionPackets) isSshConnectionResponse(size int64) bool {
	if len(s.serverPackets) == 0 {
		return true
	}

	if s.serverPackets[0] == size {
		s.serverPackets = s.serverPackets[1:]
	}

	return false
}

func (s *sshConnectionPackets) isSshConnectionRequest(size int64) bool {
	if len(s.clientPackets) == 0 {
		return true
	}

	if s.clientPackets[0] == size {
		s.clientPackets = s.clientPackets[1:]
	}

	return false
}

type session struct {
	timestamp              int64
	sshConnection          *sshConnectionPackets
	sshConnectionResponses bool
	sshConnectionRequests  bool
	httpGets               int64
	httpPosts              int64
	httpConnects           int64
	lsshConns              int64
	httpRequests           int64
}

func newSession() *session {
	return &session{
		timestamp:     time.Now().Unix(),
		sshConnection: newSshConnectionChecker(),
	}

}

type sessionMap struct {
	sync.RWMutex
	sessions map[string]*session
}

func newSessionMap() *sessionMap {
	return &sessionMap{
		sessions: make(map[string]*session),
	}
}

func (sm *sessionMap) Get(key string) *session {
	sm.RLock()
	defer sm.RUnlock()
	return sm.sessions[key]
}

func (sm *sessionMap) Put(key string, s *session) *session {
	sm.Lock()
	defer sm.Unlock()
	sm.sessions[key] = s
	return sm.sessions[key]
}

func getSession(host string, remoteAddr string) *session {
	key := host + "|" + remoteAddr

	session := sessions.Get(key)
	if session == nil {
		session = sessions.Put(key, newSession())
	}

	return session
}

func getEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}
	for i := 0; i < 256; i++ {
		px := float64(strings.Count(data, string(byte(i)))) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}
	return entropy
}

func main() {
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":3128", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	// Search for SSH header
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		sc := newStringChecker("SSH-", r.Body)
		r.Body = sc

		return r
	})

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {

		// TODO: Read more than 16 bytes
		if r.ContentLength < 16 {
			return r
		}

		var b = make([]byte, 16)
		rb := regretable.NewRegretableReaderCloser(r.Body)
		n, _ := rb.Read(b)
		log.Println("Read:", n)
		rb.Regret()
		r.Body = rb

		// if the Content-Type contains ";" drop the right part
		detectedContentType := strings.Split(http.DetectContentType(b), ";")[0]
		headerContentType := r.Header.Get("Content-Type")

		if detectedContentType != headerContentType {
			ctx.Logf("Content-Type  mismatch -> (%s,%s)", detectedContentType,
				headerContentType)
		}

		log.Println("Entropy:", getEntropy(string(b)))

		return r
	})

	// Check if used user agent is blacklisted
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		userAgent := uA.New(r.Header.Get("User-Agent"))

		browser, _ := userAgent.Browser()

		if browser == "" {
			log.Println("No browser found in user agent")
			return r, nil
		}

		userAgents := []string{
			"Go-http-client/1.1",
		}

		for _, ua := range userAgents {
			if strings.Contains(ua, browser) {
				log.Println("User agent in black list")
				return r, nil
			}
		}

		return r, nil
	})

	// Look for ssh handcheck
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		if session.sshConnection.isSshConnectionResponse(r.ContentLength) {
			log.Println("Diffel-man exchange in responses")
			session.sshConnectionResponses = true
		}

		return r
	})

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		if session.sshConnection.isSshConnectionRequest(r.ContentLength) {
			log.Println("Diffel-man exchange in requests")
			session.sshConnectionRequests = true
		}

		return r, nil
	})

	// Count number of GET and POST
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		switch r.Method {
		case "GET":
			session.httpGets += 1
		case "POST":
			session.httpPosts += 1
		case "CONNECT":
			session.httpConnects += 1
		}

		log.Println("HTTP GETS:", session.httpGets, "HTTP POSTS:",
			session.httpPosts, "timestamp:", session.timestamp)

		if session.httpPosts > (session.httpGets + 10) {
			log.Println("Suspiscious POST requests")
		}

		if session.httpConnects > 0 {
			log.Println("Suspiscious CONNECT requests")
		}

		return r, nil
	})

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		contentLength := r.ContentLength

		if contentLength == 36 || contentLength == 76 {
			if session.lsshConns == 0 {
				session.lsshConns += 1
			}

			if session.lsshConns >= 2 {
				session.lsshConns += 1
			}
		}

		if (contentLength > 36 || contentLength > 76) && session.lsshConns >= 10 {
			log.Println("SSH TTY Keystrokes detected")
		}

		return r
	})

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		contentLength := r.ContentLength

		if contentLength == 36 || contentLength == 76 {
			if session.lsshConns == 1 {
				session.lsshConns += 1
			}

			if session.lsshConns >= 3 {
				session.lsshConns += 1
			}
		}

		return r, nil
	})

	// Check if request was valide
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		switch r.Request.Method {
		case "GET":
			rs, err := http.Get(r.Request.URL.String())
			if err != nil {
				log.Panic(err)
			}

			if rs.StatusCode != r.StatusCode {
				log.Println("Status code from replay is different")
			}
		}

		return r
	})

	// Check request content length
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if r.Method == "POST" && r.ContentLength == 0 {
			log.Println("POST request with content length equals to zero made.")
		}

		return r, nil
	})

	// Check if the number of HTTP requests is lower than 20
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		session.httpRequests++

		if session.httpRequests > 20 {
			log.Println("Numbers of HTTP requests is above 20")
		}

		return r, nil
	})

	log.Fatal(http.ListenAndServe(*addr, proxy))

}
