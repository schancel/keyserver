package main

import (
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/cashweb/keyserver/pkg/keydb"
	"github.com/cashweb/keyserver/pkg/keytp"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Info().Msg("Starting keyserver daemon.")
	user, err := user.Current()
	if err != nil {
		log.Error().Msg(err.Error())
		os.Exit(1)
	}
	cfg := &keydb.Config{
		DBPath: filepath.Join(user.HomeDir, ".bchfinger.db"),
	}
	db, err := keydb.New(cfg)
	if err != nil {
		log.Error().Msg(err.Error())
		os.Exit(1)
	}
	keyserver := keytp.New(db)
	keyserver.ListenAndServe()
}
