package main

import (
"time"

	"github.com/cashweb/keyserver/pkg/keytp"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Info().Msg("Starting keyserver daemon.")

	keyserver := keytp.New()
	keyserver.ListenAndServe()
}
