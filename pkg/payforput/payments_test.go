package payforput

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cashweb/keyserver/pkg/models"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestEnforcer(t *testing.T) {
	assert := assert.New(t)

	// Path to the key we want to update
	keyPath := "/keys/foo"

	// Create our enforcer middleware, and its endpoint
	enforcer := New("/payments", "notasecret", DefaultValidator)
	assert.NotNil(enforcer)

	///////
	// Attempt an empty put
	br := bytes.NewBuffer([]byte(""))
	response := httptest.NewRecorder()
	request, err := http.NewRequest("PUT", "http://localhost:8080"+keyPath, br)
	assert.Nil(err)
	enforcer.Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	).ServeHTTP(response, request)

	///////
	// Check that we are required to pay after a naked PUT
	assert.Equal(http.StatusPaymentRequired, response.Code, "StatusPaymentRequired response is expected")
	payRequest := &models.PaymentRequest{}
	err = proto.Unmarshal(response.Body.Bytes(), payRequest)
	assert.Nil(err)
	assert.Equal("none", payRequest.GetPkiType())
	assert.Equal(uint32(1), payRequest.GetPaymentDetailsVersion())

	// Check the response body is a valid payment request
	payDetails := &models.PaymentDetails{}
	err = proto.Unmarshal(payRequest.GetSerializedPaymentDetails(), payDetails)
	assert.Nil(err)
	assert.Equal("main", payDetails.GetNetwork())
	assert.True(payDetails.GetExpires() > payDetails.GetTime())
	assert.True(uint64(time.Now().Unix()) >= payDetails.GetTime())
	assert.Equal("/payments", payDetails.GetPaymentUrl())
	assert.Equal([]byte("http://localhost:8080"+keyPath), payDetails.GetMerchantData())

	// Create our payment
	payment := &models.Payment{
		MerchantData: payDetails.GetMerchantData(),
	}
	paymentBytes, err := proto.Marshal(payment)
	assert.Nil(err)

	///////
	// Check that headers are enforced on POST to the payment url
	payBody := bytes.NewBuffer(paymentBytes)
	response = httptest.NewRecorder()
	request, err = http.NewRequest("POST", payDetails.GetPaymentUrl(), payBody)
	assert.Nil(err)
	enforcer.PaymentHandler(response, request)
	assert.Equal(http.StatusUnsupportedMediaType, response.Code, "StatusUnsupportedMediaType response is expected")
	///////
	// Check that payment url gives us back a payment ack, and a token
	request, err = http.NewRequest("POST", payDetails.GetPaymentUrl(), payBody)
	assert.Nil(err)
	request.Header.Add("Content-Type", "application/bitcoin-payment")
	request.Header.Add("Accept", "application/bitcoin-paymentack")
	response = httptest.NewRecorder()
	enforcer.PaymentHandler(response, request)
	assert.Equal(http.StatusFound, response.Code, "StatusFound response is expected")
	payAck := &models.PaymentACK{}
	err = proto.Unmarshal(response.Body.Bytes(), payAck)
	assert.Nil(err)
	assert.True(proto.Equal(payAck.GetPayment(), payment), "PaymentAck didn't send back payment")

	// Check that the token is set correctly in both places.
	auth := response.Header().Get("Authorization")
	loc := response.Header().Get("Location")
	redirectURL, err := url.Parse(loc)
	assert.Equal(keyPath, redirectURL.Path)
	assert.Equal("POP "+redirectURL.Query().Get("code"), auth)

	///////
	// Test that the token works with a `code` queryparam
	br = bytes.NewBuffer([]byte(""))
	response = httptest.NewRecorder()
	request, err = http.NewRequest("PUT", loc, br)
	assert.Nil(err)
	assert.True(DefaultValidator(request, enforcer.Secret), "Token is not valid")
	enforcer.Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body.Close()
			w.WriteHeader(http.StatusOK)
		}),
	).ServeHTTP(response, request)
	assert.Equal(http.StatusOK, response.Code, "StatusOK response is expected")

	///////
	// Try using as a POP token
	response = httptest.NewRecorder()
	request, err = http.NewRequest("PUT", "http://localhost:8080"+keyPath, br)
	assert.Nil(err)
	request.Header.Add("Authorization", auth)
	assert.True(DefaultValidator(request, enforcer.Secret), "Token is not valid")
	enforcer.Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body.Close()
			w.WriteHeader(http.StatusOK)
		}),
	).ServeHTTP(response, request)
	assert.Equal(http.StatusOK, response.Code, "StatusOK response is expected")
}
