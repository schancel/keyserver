package keydb

import (
	"crypto/sha256"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cashweb/keyserver/pkg/models"
	"github.com/gcash/bchd/bchec"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestAddressSignVerify(t *testing.T) {
	assert := assert.New(t)
	privKey, err := bchec.NewPrivateKey(bchec.S256())
	assert.Nil(err)
	pubkey := privKey.PubKey()
	t.Log(len(pubkey.SerializeCompressed()))
	addr, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(pubkey.SerializeUncompressed()), &chaincfg.MainNetParams)
	assert.Nil(err)
	assert.Equal(addr.ScriptAddress(), bchutil.Hash160(pubkey.SerializeUncompressed()))
	t.Log(addr.ScriptAddress())
	sig, err := privKey.SignSchnorr(addr.ScriptAddress())
	assert.Nil(err)
	valid := sig.Verify(addr.ScriptAddress(), pubkey)
	assert.True(valid)
}

func TestSetGet(t *testing.T) {
	assert := assert.New(t)

	// Setup a DB
	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	cfg := &Config{
		DBPath: filepath.Join(dir, "testsetget.db"),
	}
	keyDb, err := New(cfg)
	assert.Nil(err)

	// Generate a privkey
	privKey, err := bchec.NewPrivateKey(bchec.S256())
	assert.Nil(err)
	pubkey := privKey.PubKey()
	// Find the address (Note: legacy atm)
	addr, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(pubkey.SerializeUncompressed()), &chaincfg.MainNetParams)
	assert.Nil(err)

	addrMetadata := &models.AddressMetadata{
		PubKey: pubkey.SerializeUncompressed(),
		Payload: &models.Payload{
			Timestamp: time.Now().Unix(),
			Rows: []*models.MetadataField{
				&models.MetadataField{
					Headers: []*models.Header{
						&models.Header{
							Name:  "Type",
							Value: "EgoBoost",
						},
					},
					Metadata: []byte("Shammah has such great ideas... or something"),
				},
			},
		},
	}
	rawMetadata, err := proto.Marshal(addrMetadata.GetPayload())
	assert.Nil(err)

	msgHash := sha256.Sum256(rawMetadata)
	sig, err := privKey.SignSchnorr(msgHash[:])
	assert.Nil(err)
	addrMetadata.Signature = sig.Serialize()

	err = keyDb.Set(addr.EncodeAddress(), addrMetadata)
	assert.Nil(err)
	fetchedMetadata, err := keyDb.Get(addr.EncodeAddress())
	assert.Nil(err)
	assert.True(proto.Equal(addrMetadata, fetchedMetadata), "Fetch value did not match expected value")
}
