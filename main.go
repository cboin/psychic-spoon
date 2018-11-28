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
	session *session
}

func newStringChecker(s string, r io.ReadCloser, ss *session) *stringChecker {
	return &stringChecker{
		pattern: s,
		reader:  r,
		session: ss,
	}
}

func (s *stringChecker) Read(p []byte) (n int, err error) {
	n, err = s.reader.Read(p)

	if bytes.Contains(p[:n], []byte(s.pattern)) {
		if !s.session.hasPattern {
			s.session.score += 50
			s.session.hasPattern = true
		}
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
	sshConnection          *sshConnectionPackets
	sshConnectionResponses bool
	sshConnectionRequests  bool
	httpGets               int64
	httpPosts              int64
	httpConnects           int64
	httpRequests           int64
	hasPattern             bool
	hasUserAgent           bool
	score                  int64
}

func newSession() *session {
	return &session{
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

// Add a client <-> server session
func (sm *sessionMap) Put(key string, s *session) *session {
	sm.Lock()
	defer sm.Unlock()
	sm.sessions[key] = s
	return sm.sessions[key]
}

// Given a client <-> server session
func getSession(host string, remoteAddr string) *session {
	key := host + "|" + remoteAddr

	session := sessions.Get(key)
	if session == nil {
		session = sessions.Put(key, newSession())
	}

	return session
}

// NOT USED
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
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		sc := newStringChecker("SSH-", r.Body, session)
		r.Body = sc

		return r
	})

	// Find if the given content type match a detected content type
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		if r.ContentLength == -1 {
			return r
		}

		// Read no more than 500 bytes
		var willRead int64 = 500
		if r.ContentLength < willRead {
			willRead = r.ContentLength
		}
		var b = make([]byte, willRead)
		rb := regretable.NewRegretableReaderCloser(r.Body)
		n, _ := rb.Read(b)
		// Return the body to the initial state
		rb.Regret()
		r.Body = rb

		// if the Content-Type contains ";" drop the right part
		detectedContentType := strings.Split(http.DetectContentType(b[:n]), ";")[0]
		headerContentType := strings.Split(r.Header.Get("Content-Type"), ";")[0]

		if detectedContentType != headerContentType {
			ctx.Logf("Content type mismatch")
			session.score += 1
		}

		return r
	})

	// Check if used user agent is blacklisted
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		userAgent := uA.New(r.Header.Get("User-Agent"))

		browser, _ := userAgent.Browser()

		if !session.hasUserAgent {

			if browser == "" {
				ctx.Logf("Empty user agent")
				session.score += 10
				session.hasUserAgent = true
				return r, nil
			}

			userAgents := []string{
				"Go-http-client/1.1",
			}

			for _, ua := range userAgents {
				if strings.Contains(ua, browser) {
					session.score += 5
					session.hasUserAgent = true
					return r, nil
				}
			}

		}

		return r, nil
	})

	// Look for SSH handcheck
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		if r.ContentLength == 0 {
			ctx.Logf("Content length equals to zero")
			return r
		}

		if session.sshConnection.isSshConnectionResponse(r.ContentLength) {
			session.sshConnectionResponses = true
			ctx.Logf("SSH key exchanges found in response")
			session.score += 25
		}

		if session.sshConnection.isSshConnectionRequest(r.Request.ContentLength) {
			session.sshConnectionRequests = true
			ctx.Logf("SSH key exchanges found in request")
			session.score += 25
		}

		return r
	})

	// Count number of GET, POST and CONNECT
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

		if session.httpPosts > (session.httpGets + 10) {
			ctx.Logf("Too many HTTP post requests made")
			session.score += 15
		}

		if session.httpConnects > 5 {
			ctx.Logf("More than 5 HTTP connects made")
			session.score += 10
		}

		return r, nil
	})

	// Check if request was valide by replaying it
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		switch r.Request.Method {
		case "GET":
			rs, err := http.Get(r.Request.URL.String())
			if err != nil {
				log.Panic(err)
			}
			defer rs.Body.Close()

			if rs.StatusCode != r.StatusCode {
				ctx.Logf("HTTP Request status code mismatch")
				session.score += 5
			}
		}

		return r
	})

	// Check if response content length is zero
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		if r.Request.Method == "POST" && r.Request.ContentLength == 0 {
			ctx.Logf("HTTP Post request with empty content length")
			session.score += 5
		}

		if r.ContentLength == 0 {
			ctx.Logf("Response with empty content length")
			session.score += 5
		}

		return r
	})

	// Check if the number of HTTP requests is lower than 300
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		session.httpRequests++

		if session.httpRequests > 300 {
			ctx.Logf("HTTP Requests above 300")
			session.score += 5
		}

		return r, nil
	})

	// Search for echoed back http packets
	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		ip, _, err := net.SplitHostPort(r.Request.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Request.Host, ip)

		if r.ContentLength == 0 {
			return r
		}

		if r.Request.ContentLength == r.ContentLength {
			ctx.Logf("Echoed back HTTP packets")
			session.score += 20
		}

		return r
	})

	// Pass or not ?
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}
		session := getSession(r.Host, ip)

		if session.score >= 100 {
			ctx.Logf("SSH tunnel detected")
			return r, goproxy.NewResponse(r,
				goproxy.ContentTypeText, http.StatusForbidden,
				"SSH tunnel detected")
		}

		return r, nil
	})

	// Start cleaner
	go startAutoDecrement()

	// Start server
	log.Fatal(http.ListenAndServe(*addr, proxy))

}

// Decrement the score of each clients by 10 every 30
func startAutoDecrement() {
	for {
		sessions.RLock()
		for _, v := range sessions.sessions {
			v.score -= 20
		}
		sessions.RUnlock()
		time.Sleep(time.Second * 30)
	}
}
