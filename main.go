package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/regretable"
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

	log.Fatal(http.ListenAndServe(*addr, proxy))
}
