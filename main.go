package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
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

func (s *sshConnectionPackets) isSshConnectipnRequest(size int64) bool {
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
	log.Println("getSession(host:", host, ",", remoteAddr, ")")
	key := "Request|" + host + "|" + remoteAddr

	session := sessions.Get(key)
	if session == nil {
		session = sessions.Put(key, newSession())
	}

	return session
}

func main() {
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":3128", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		sc := newStringChecker("SSH-_", r.Body)
		r.Body = sc

		return r
	})

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		threshold := 16
		contentLengthText := r.Header.Get("Content-Length")

		contentLength, err := strconv.Atoi(contentLengthText)
		if err != nil {
			log.Fatal(err)
		}

		if contentLength < threshold {
			log.Println("Body under threshold")
			return r
		}

		var b = make([]byte, 16)
		rb := regretable.NewRegretableReaderCloser(r.Body)
		rb.Read(b)
		rb.Regret()
		r.Body = rb

		// if the Content-Type contains ";" drop the right part
		detectedContentType := strings.Split(http.DetectContentType(b), ";")[0]
		headerContentType := r.Header.Get("Content-Type")

		if detectedContentType != headerContentType {
			ctx.Logf("Content-Type  mismatch -> (%s,%s)", detectedContentType,
				headerContentType)
		}

		return r
	})

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

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		log.Println("Response Content-Length:", r.ContentLength)

		return r
	})

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		buf := make([]byte, 1024)
		rb := regretable.NewRegretableReaderCloser(r.Body)
		rb.Read(buf)
		rb.Regret()
		r.Body = rb

		log.Println(string(buf))

		return r
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

		if session.sshConnection.isSshConnectipnRequest(r.ContentLength) {
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

	log.Fatal(http.ListenAndServe(*addr, proxy))

}
