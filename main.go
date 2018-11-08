package main

import (
	"bytes"
	"flag"
	"github.com/elazarl/goproxy"
	"io"
	"log"
	"net/http"
)

type stringChecker struct {
	string string
	match  bool
	reader io.ReadCloser
}

func newStringChecker(s string, r io.ReadCloser) *stringChecker {
	return &stringChecker{s, false, r}
}

func (s *stringChecker) Read(p []byte) (n int, err error) {
	n, err = s.reader.Read(p)

	if bytes.Contains(p[:n], []byte(s.string)) {
		s.match = true
	}

	return
}

func (s *stringChecker) Close() error {
	return s.reader.Close()
}

func main() {
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":3128", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	proxy.OnResponse().DoFunc(func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		sc := newStringChecker("SSH", r.Body)
		if sc.match {
			log.Println("SSH found")
		}
		r.Body = sc

		return r
	})

	log.Fatal(http.ListenAndServe(*addr, proxy))
}
