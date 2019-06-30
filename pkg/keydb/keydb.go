package keydb

import (
	"github.com/boltdb/bolt"
)

type KeyDB struct {
	db *bolt.DB
}

// New returns a new KeyDB that can be used by the keytp server.
func New() *KeyDB {
	return &KeyDB{}
}