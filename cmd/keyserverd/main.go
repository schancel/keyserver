package main

import (
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/cashweb/keyserver/pkg/keydb"
	"github.com/cashweb/keyserver/pkg/keytp"
	"github.com/cashweb/keyserver/pkg/payforput"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	zerolog.TimeFieldFormat = time.RFC3339
	var rootCmd = &cobra.Command{
		Use:   "keyserver",
		Short: "Cash:web keyserverd is a BCH-based key and metadata server",
		Long: `
Cash:web keyserverd is a BCH-based key and metadata server. It enables
wallets to provide various information about the capabilities of the keys
associated with a particular Bitcoin Cash address, as well as the pubkey
for the address.  This enables distribtued and encrypted communication
natively using Bitcoin Cash primitives.

The source is available here: https://github.com/cashweb/keyserver`,
		PersistentPreRunE: SetupConfiguration,
		RunE:              ExecServer,
	}

	// Find user information
	usr, err := user.Current()
	if err != nil {
		log.Error().Msg(err.Error())
		os.Exit(1)
	}

	rootCmd.Flags().StringP("config", "c", "", "Configuration file")
	rootCmd.Flags().StringP("bind", "b", "0.0.0.0:8080", "Bind Address for keyserverd")
	rootCmd.Flags().StringArrayP("peer", "p", []string{}, "URL to a keyserver peer")
	rootCmd.Flags().StringP("secret", "s", payforput.RandString(64), "Secret string for HMAC tokens")
	rootCmd.Flags().StringP("dbpath", "d", filepath.Join(usr.HomeDir, "/.keyserver/database.db"), "Location that boltdb files should be expected.")

	viper.BindPFlag("bind", rootCmd.Flags().Lookup("bind"))
	viper.BindPFlag("peers", rootCmd.Flags().Lookup("peer"))
	viper.BindPFlag("secret", rootCmd.Flags().Lookup("secret"))
	viper.BindPFlag("dbpath", rootCmd.Flags().Lookup("dbpath"))

	if err := rootCmd.Execute(); err != nil {
		log.Error().Msg(err.Error())
		os.Exit(1)
	}
}

// SetupConfiguration sets up viper for the appropriate configuration paths and defaults
func SetupConfiguration(ccmd *cobra.Command, args []string) error {
	viper.SetConfigName("config.yaml")       // name of config file (without extension)
	viper.AddConfigPath("/etc/keyserver/")   // path to look for the config file in
	viper.AddConfigPath("$HOME/.keyserver/") // call multiple times to add many search paths

	// Allow specifying an explicit config file
	configName, err := ccmd.Flags().GetString("config")
	if err != nil {
		return err
	}
	if ccmd.Flags().Changed("config") {
		viper.SetConfigFile(configName)
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		return err
	}
	return nil
}

// ExecServer runs the root functionality of the keyserver
func ExecServer(cmd *cobra.Command, args []string) error {
	log.Info().Msg("Starting keyserver daemon.")
	dbpath := viper.GetString("dbpath")
	err := os.MkdirAll(filepath.Dir(dbpath), 0700)
	cfg := &keydb.Config{
		DBPath: dbpath,
	}
	db, err := keydb.New(cfg)
	if err != nil {
		return err
	}
	keyserver := keytp.New(db)
	return keyserver.ListenAndServe()
}
