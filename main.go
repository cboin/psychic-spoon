package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/regretable"
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

type sshHandCheckPktSize struct {
	clientPktSize []int64
	serverPktSize []int64
}

func newSshHandCheckPktSize() *sshHandCheckPktSize {
	var ps sshHandCheckPktSize
	ps.clientPktSize = []int64{21, 1392, 48, 16}
	ps.serverPktSize = []int64{21, 1080, 452}

	return &ps
}

func (s *sshHandCheckPktSize) hasReceivedPacket(size int64) bool {
	if len(s.serverPktSize) == 0 {
		return true
	}

	if s.serverPktSize[0] == size {
		s.serverPktSize = s.serverPktSize[1:]
	}

	return false
}

func (s *sshHandCheckPktSize) hasSendedRequest(size int64) bool {
	if len(s.clientPktSize) == 0 {
		return true
	}

	if s.clientPktSize[0] == size {
		s.clientPktSize = s.clientPktSize[1:]
	}

	return false
}

type session struct {
	timestamp                       int64
	sshHandCheck                    *sshHandCheckPktSize
	hasFoundSshHandCheckInResponses bool
	hasFoundSshHandCheckInRequests  bool
}

func newSession() *session {
	return &session{time.Now().Unix(), newSshHandCheckPktSize(), false, false}
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

func main() {
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":3128", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		sc := newStringChecker("SSH-2.0-OpenSSH_", r.Body)
		r.Body = sc

		return r
	})

	/* checks if the detected content type match the content type given
	   in the http header. */
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
		ctx.Logf(r.Header.Get("User-agent"))

		return r, nil
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
		key := "Response|" + r.Request.Host + "|" + r.Request.RemoteAddr

		session := sessions.Get(key)
		if session == nil {
			session = sessions.Put(key, newSession())
		} else if session.hasFoundSshHandCheckInResponses {
			return r
		}

		if session.sshHandCheck.hasReceivedPacket(r.ContentLength) {
			log.Println("SSH handcheck found in responses")
			session.hasFoundSshHandCheckInResponses = true
		}

		return r
	})

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		key := "Request|" + r.Host + "|" + r.RemoteAddr

		session := sessions.Get(key)
		if session == nil {
			session = sessions.Put(key, newSession())
		} else if session.hasFoundSshHandCheckInRequests {
			return r, nil
		}

		if session.sshHandCheck.hasSendedRequest(r.ContentLength) {
			log.Println("SSH handcheck found in requests")
			session.hasFoundSshHandCheckInRequests = true
		}

		return r, nil
	})

	log.Fatal(http.ListenAndServe(*addr, proxy))
}
