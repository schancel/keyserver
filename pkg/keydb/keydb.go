package keydb

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cashweb/keyserver/pkg/models"
	"go.etcd.io/bbolt"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"

	"github.com/gcash/bchd/bchec"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
)

// Bucket namespace.  This is UTF-8 for "addressMetadata"
var addressMetadataBucket = []byte{0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61}

// Config is the configuration for creating a new keyDb instance
type Config struct {
	DBPath string
}

// KeyDB is an implementation of a kv store which is permissioned using pubkey based authentication
type KeyDB struct {
	db *bbolt.DB
}

// New returns a new KeyDB that can be used by the keytp server.
func New(config *Config) (*KeyDB, error) {
	if config.DBPath == "" {
		return nil, errors.New("no DBPath provided in config")
	}

	db, err := bbolt.Open(config.DBPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open db")
	}

	// Ensure our bucket exists
	// TODO: We should probably use cascading buckets that can be deleted
	// routinely for garbage collection.  Wallets can readvertise occasionally
	// if they want to keep their metadata up to date and online.
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(addressMetadataBucket)
		if err != nil {
			return errors.Wrapf(err, "failed to create bucket")
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return &KeyDB{db: db}, nil
}

// Set expects to take a cryptocurrency address and update a key in the DB backend if the
// payload is valid under the key provided.
func (db *KeyDB) Set(keyAddress string, metadata *models.AddressMetadata) error {
	// Treat the key as a payment address for BCH
	addr, err := bchutil.DecodeAddress(keyAddress, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	// Get the hash160 of the pubkey.  This should be RIPEMD(SHA256(PubKey)), although this
	// will change depending on the type of address.
	keyHash := addr.ScriptAddress()
	rawPubKey := metadata.GetPubKey()
	computedHash := bchutil.Hash160(rawPubKey)
	if !bytes.Equal(computedHash, keyHash) {
		return fmt.Errorf("pubKey does not match address: %q != %q", computedHash, keyHash)
	}

	// Check to make sure this is actually an update and not someone resubmitting an old
	// value
	oldValue, err := db.Get(keyAddress)
	if err == nil && oldValue.GetPayload().GetTimestamp() > metadata.Payload.GetTimestamp() {
		return errors.New("outdated value attempting to be used as an update")
	}

	// TODO: Ensure we're not re-adding keys that are older than the GC interval.

	pubKey, err := bchec.ParsePubKey(rawPubKey, bchec.S256())
	if err != nil {
		return err
	}

	rawPayload, err := proto.Marshal(metadata.GetPayload())
	if err != nil {
		return err
	}
	msgHash := sha256.Sum256(rawPayload)
	var sig *bchec.Signature
	switch metadata.GetType() {
	case models.AddressMetadata_Schnorr:
		sig, err = bchec.ParseSchnorrSignature(metadata.GetSignature())
	case models.AddressMetadata_ECDSA:
		sig, err = bchec.ParseDERSignature(metadata.GetSignature(), bchec.S256())
	}
	if err != nil {
		return err
	}
	// Verify the signature against the SHA256 of the message
	if !sig.Verify(msgHash[:], pubKey) {
		return errors.New("Signature does match")
	}

	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(addressMetadataBucket)
		metadata, err := proto.Marshal(metadata)
		if err != nil {
			return err
		}
		err = b.Put([]byte(keyAddress), metadata)
		return err
	})
}

// Get pulls a key from the database, and returns it to the called.  It does not validate
// the output data and expects that the integrety of values was ensured during SetKey()
func (db *KeyDB) Get(keyAddress string) (*models.AddressMetadata, error) {
	metadata := &models.AddressMetadata{}
	err := db.db.View(func(tx *bbolt.Tx) error {
		bk := tx.Bucket(addressMetadataBucket)
		if bk == nil {
			return errors.Wrap(bbolt.ErrBucketNotFound, "failed to get 'addressMetadata' bucket")
		}

		rawMetadata := bk.Get([]byte(keyAddress))
		if rawMetadata == nil {
			return errors.Wrap(bbolt.ErrBucketNotFound, "failed to find address metadata")
		}

		err := proto.Unmarshal(rawMetadata, metadata)
		return err
	})
	return metadata, err
}

// Close closed down the db, and releases the lock on the db file
func (db *KeyDB) Close() {
	db.db.Close()
}
