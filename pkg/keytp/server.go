package keytp

import (
	"log"
	"net/http"
	"time"
)

type HTTPKeyServer struct {
	server *http.Server
}

// New returns a HTTP-based keyserver that implements the REST api to handle keys
func New() *HTTPKeyServer {
	s := &http.Server{
		Addr:           ":8080",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Fatal(s.ListenAndServe())

	return &HTTPKeyServer{
		server: s,
	}
}

// ListenAndServe listens and serves requests
func (s *HTTPKeyServer) ListenAndServe() {
	s.server.ListenAndServe()
}
