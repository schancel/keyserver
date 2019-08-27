package payforput

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/cashweb/keyserver/pkg/models"

	"github.com/golang/protobuf/proto"
	"github.com/rs/zerolog/hlog"
)

// ValidatorFunc is the type of unction which can indicate if a request has
// the appropriate headers to have been paid.
type ValidatorFunc func(r *http.Request, secret string) bool

// PaymentEnforcer ensures that the request has been paid for properly by
// checking for a payment authorization. If there is no payment authorization
// header, then we send a BIP70 payment request
type PaymentEnforcer struct {
	// Location to where we should redirect payments, and has the PaymentHandler
	// installed
	PaymentURL string
	// Validator is a func that validates that a request has a valid proof of
	// payment
	Validator ValidatorFunc
	// Secret is the HMAC secret used for generating and validating tokens
	// NOTE: This may be swapped out at a later date.
	Secret string
}

// New returns a new payment enforcer that can be used for easy BIP70 integration
// for the keyserver.
func New(PaymentURL string, secret string, Validator ValidatorFunc) *PaymentEnforcer {
	pe := &PaymentEnforcer{
		PaymentURL: PaymentURL,
		Validator:  Validator,
		Secret:     secret,
	}
	if pe.Validator == nil {
		pe.Validator = DefaultValidator
	}
	// Generate an ephemeral secret and hold on to it
	if pe.Secret == "" {
		pe.Secret = RandString(64)
	}

	return pe
}

// DefaultValidator is the default request payment validator
func DefaultValidator(r *http.Request, secret string) bool {
	// First attempt to get the code from the querystring
	token := r.URL.Query().Get("code")

	headerToken := r.Header.Get("Authorization")
	// If we had an Authorization header, use that instead.
	if headerToken != "" && len(headerToken) >= 4 && headerToken[0:4] == "POP " {
		token = headerToken[4:]
	}

	// Remove the code query param, as it wasn't part of the HMAC hash
	url := *r.URL
	url.RawQuery = ""
	// Validate that the HMAC is valid for this URL.
	return ValidateHMACToken(url.String(), token, secret)
}

// PaymentHandler is an http handler that implements a check for payment,
// along with a redirect to the original location with the key
func (e *PaymentEnforcer) PaymentHandler(w http.ResponseWriter,
	r *http.Request) {
	log := hlog.FromRequest(r)
	defer r.Body.Close()

	// Check BIP70 headers
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/bitcoincash-payment" {
		http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
		return
	}
	acceptHeader := r.Header.Get("Accept")
	if acceptHeader != "application/bitcoincash-paymentack" {
		http.Error(w, "invalid content type", http.StatusNotAcceptable)
		return
	}

	// Read the Payment information
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error().Msgf("unable to read request body: %s", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	payment := &models.Payment{}
	err = proto.Unmarshal(body, payment)
	if err != nil {
		log.Error().Msgf("unable to unmarshal payment: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	///////
	// TODO: Check outputs
	///////
	log.Info().Str("memo", payment.GetMemo()).Msg("Payment received")

	// Acknowledge the payment, and redirect back to the intended location.
	memo := "Thank you for being a customer"
	payAck := &models.PaymentACK{
		Payment: payment,
		Memo:    &memo,
	}
	payAckBytes, err := proto.Marshal(payAck)
	if err != nil {
		log.Error().Msgf("unable to unmarshal payment: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Provide a payment token
	// TODO: Maybe generate something with some metadata
	token := GenerateHMACToken(string(payment.GetMerchantData()), e.Secret)
	loc, err := url.Parse(string(payment.GetMerchantData()))
	if err != nil {
		log.Error().Msgf("unable to parse merchent data: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Set up the response
	// Add the token to the response header for ease of use.
	q := loc.Query()
	q.Set("code", token)
	loc.RawQuery = q.Encode()
	w.Header().Set("Authorization", "POP "+token)
	w.Header().Set("Location", loc.String())
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusFound)
	w.Write(payAckBytes)
}

// Middleware is a middleware function that ensures a payment has been made
// before allowing this endpoint to be accessed.
func (e *PaymentEnforcer) Middleware(prevHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := hlog.FromRequest(r)

		// If we have a valid payment, carry on
		if e.Validator == nil || e.Validator(r, e.Secret) {
			prevHandler.ServeHTTP(w, r)
			return
		}
		// Close the request after we're done here.  They didn't have a valid payment yet
		defer r.Body.Close()

		// NOTE: This could just fetch an invoice from a BIP70 server, but this is
		// straightforward for a standalone and easy to install version of this
		// keyserver.  A lot more can be done if this becomes popular (e.g. we need peering)

		// TODO: Actually create some outputs.  However, for now, ensuring we can request a
		// payment properly is sufficient.

		// Create the payment details
		network := "main"
		curTime := uint64(time.Now().Unix())
		expireTime := uint64(time.Now().Add(10 * time.Second).Unix())
		// Strip querystring since encoding and decoding might disrupt HMAC
		url := *r.URL
		url.RawQuery = ""
		pd := &models.PaymentDetails{
			Network:    &network,
			Time:       &curTime,
			Expires:    &expireTime,
			PaymentUrl: &e.PaymentURL,
			// Set the current URL to the merchant data.
			// TODO: Probably should be more here.
			MerchantData: []byte(url.String()),
		}
		// Construct and send the payment request
		pdBytes, err := proto.Marshal(pd)
		if err != nil {
			log.Error().Msgf("unable to marshal request to PROTO: %s", err)
			http.Error(w, "internal server error",
				http.StatusInternalServerError)
			return
		}
		// TODO: We need to enable this to be signed, but for that to work the
		// server needs a valid X509 certificate.  It would probably be good to delegate obtaining
		// an invoice from a BIP70 server.
		pkiType := "none"
		pdVersion := uint32(1)
		pr := &models.PaymentRequest{
			PaymentDetailsVersion:    &pdVersion,
			PkiType:                  &pkiType,
			SerializedPaymentDetails: pdBytes,
		}
		resp, err := proto.Marshal(pr)
		if err != nil {
			log.Error().Msgf("unable to marshal request to proto: %s", err)
			http.Error(w, "internal server error",
				http.StatusInternalServerError)
			return
		}

		// Send the payment request
                w.Header().Set("Content-Type", "application/bitcoincash-paymentrequest")
                w.Header().Set("Content-Transfer-Encoding", "binary")
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write(resp)
	})
}
