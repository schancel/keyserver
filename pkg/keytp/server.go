package keytp

import (
	"net/http"
	"time"

	"github.com/cashweb/keyserver/pkg/models"
	"github.com/cashweb/keyserver/pkg/payforput"

	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

const (
	serverPort = ":8080"
)

type HTTPKeyServer struct {
	mux *chi.Mux
	db  Database
}

// Data is the expected interface for an HTTPKeyServer's database
type Database interface {
	Get(string) (*models.AddressMetadata, error)
	Set(string, *models.AddressMetadata) error
}

// New returns a HTTP-based keyserver that implements the REST api to handle keys
func New(db Database) *HTTPKeyServer {
	mux := chi.NewRouter()
	setupBaseMiddleware(mux)
	server := &HTTPKeyServer{
		mux: mux,
		db:  db,
	}

	enforcer := payforput.New("/payments", nil)
	mux.Route("/", func(r chi.Router) {
		r.Get("/", http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.Write([]byte("You have found a keytp server."))
			req.Body.Close()
		}))
		// Install our payment enforcer at the appropriate path
		r.Post(enforcer.PaymentURL, enforcer.PaymentHandler)
	})

	// Install our normal paths
	mux.Route("/keys/{keyID}", func(r chi.Router) {
		r.With(enforcer.Middleware).Put("/", server.setKey)
		r.Get("/", server.getKey)
	})
	return server
}

func setupBaseMiddleware(mux *chi.Mux) {
	mux.Use(middleware.Timeout(10 * time.Second))
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(hlog.NewHandler(log.Logger))
	mux.Use(hlog.RemoteAddrHandler("ip"))
	mux.Use(hlog.RefererHandler("referer"))
	mux.Use(hlog.AccessHandler(func(req *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(req).Info().
			Str("method", req.Method).
			Int("size", size).
			Dur("duration", duration).
			Int("status", status).
			Msg("")
	}))
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.URLFormat)
}

// ListenAndServe listens and serves requests
func (s *HTTPKeyServer) ListenAndServe() {
	http.ListenAndServe(serverPort, s.mux)
}
