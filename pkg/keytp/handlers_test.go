package keytp

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mocks "github.com/cashweb/keyserver/pkg/keytp/mocks"
	"github.com/cashweb/keyserver/pkg/models"
	"github.com/gcash/bchd/bchec"
	"github.com/go-chi/chi"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestSetKey(t *testing.T) {
	assert := assert.New(t)
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDB := mocks.NewMockDatabase(mockCtrl)

	privKey, err := bchec.NewPrivateKey(bchec.S256())
	assert.Nil(err)
	pubkey := privKey.PubKey()
	addrMetadata := &models.AddressMetadata{
		PubKey: pubkey.SerializeUncompressed(),
		Payload: &models.Payload{
			Timestamp: time.Now().Unix(),
			Entries: []*models.Entry{
				&models.Entry{
					Kind: "EgoBoost",
					Headers: []*models.Header{
						&models.Header{
							Name:  "Junk",
							Value: "Data",
						},
					},
					EntryData: []byte("Shammah has such great ideas... or something"),
				},
			},
		},
	}

	addMetadataBytes, err := proto.Marshal(addrMetadata)
	assert.Nil(err)

	mockDB.EXPECT().Set("foo", gomock.Any()).Times(1)
	server := New(mockDB)

	req, err := http.NewRequest("PUT", "/keys/foo", bytes.NewBuffer(addMetadataBytes))
	assert.Nil(err)

	rr := httptest.NewRecorder()
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("keyID", "foo")

	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	handler := http.HandlerFunc(server.setKey)
	handler.ServeHTTP(rr, req)

	assert.Equal(rr.Code, http.StatusOK)
}

func TestGetKey(t *testing.T) {
	assert := assert.New(t)
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDB := mocks.NewMockDatabase(mockCtrl)

	privKey, err := bchec.NewPrivateKey(bchec.S256())
	assert.Nil(err)
	pubkey := privKey.PubKey()
	addrMetadata := &models.AddressMetadata{
		PubKey: pubkey.SerializeUncompressed(),
		Payload: &models.Payload{
			Timestamp: time.Now().Unix(),
			Entries: []*models.Entry{
				&models.Entry{
					Kind: "EgoBoost",
					Headers: []*models.Header{
						&models.Header{
							Name:  "Junk",
							Value: "Data",
						},
					},
					EntryData: []byte("Shammah has such great ideas... or something"),
				},
			},
		},
	}

	addMetadataBytes, err := proto.Marshal(addrMetadata)
	assert.Nil(err)

	mockDB.EXPECT().Get("foo").Return(addrMetadata, nil).Times(1)
	server := New(mockDB)

	req, err := http.NewRequest("GET", "/keys/foo", bytes.NewBuffer([]byte("")))
	assert.Nil(err)

	rr := httptest.NewRecorder()
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("keyID", "foo")

	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	handler := http.HandlerFunc(server.getKey)
	handler.ServeHTTP(rr, req)

	assert.Equal(rr.Code, http.StatusOK)

	returnedBytes, err := ioutil.ReadAll(rr.Body)
	assert.Nil(err)

	assert.Equal(returnedBytes, addMetadataBytes)
}
