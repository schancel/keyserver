package payforput

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateVerifyToken(t *testing.T) {
	assert := assert.New(t)
	secret := RandString(64)
	message := RandString(64)

	token := GenerateHMACToken(message, secret)
	assert.True(ValidateHMACToken(message, token, secret))
	assert.False(ValidateHMACToken("not the message", token, secret))
	assert.False(ValidateHMACToken(message, token, "not the secret"))
}
