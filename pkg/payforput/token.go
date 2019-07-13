package payforput

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
)

// GenerateHMACToken generates an HMAC token for a given url with the provided secret
func GenerateHMACToken(message, secret string) string {
	return base64.URLEncoding.EncodeToString(generateHMACTokenRaw(message, secret))
}

// ValidateHMACToken validates that an HMAC token matches for a given URL
func ValidateHMACToken(message, messageMAC64, secret string) bool {
	expectedMAC := generateHMACTokenRaw(message, secret)
	messageMAC, err := base64.URLEncoding.DecodeString(messageMAC64)
	if err != nil {
		return false
	}
	return hmac.Equal(messageMAC, expectedMAC)
}

func generateHMACTokenRaw(message, secret string) []byte {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(message))

	return h.Sum(nil)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// RandString is a random string implementation taken from
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
// It implements an easy way to get an ephemeral HMAC secret if one is not configured.
func RandString(n int) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
