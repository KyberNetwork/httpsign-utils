package authenticator

import (
	"errors"
	"strings"

	"github.com/gin-contrib/httpsign"
	"github.com/gin-contrib/httpsign/crypto"
	"github.com/gin-contrib/httpsign/validator"
)

// KeyPair includes key and secretKey with format accessKeyID:secretAccessKey
type KeyPair string

// NewAuthenticator create a httpsign.Authenticator to check the message signing is valid or not
func NewAuthenticator(keyPairs ...KeyPair) (*httpsign.Authenticator, error) {
	var secrets = make(httpsign.Secrets)

	if len(keyPairs) == 0 {
		return nil, errors.New("keyPairs are required")
	}

	for _, keyPair := range keyPairs {
		key, secret, err := ParseKeyPair(keyPair)
		if err != nil {
			return nil, err
		}
		signKeyID := httpsign.KeyID(key)
		secrets[signKeyID] = &httpsign.Secret{
			Key:       secret,
			Algorithm: &crypto.HmacSha512{},
		}
	}

	auth := httpsign.NewAuthenticator(
		secrets,
		httpsign.WithValidator(
			NewNonceValidator(),
			validator.NewDigestValidator(),
		),
		httpsign.WithRequiredHeaders(
			[]string{"(request-target)", "nonce", "digest"},
		),
	)
	return auth, nil
}

// ParseKeyPair parse keyPair to accessKeyID and secretAccessKey
func ParseKeyPair(keyPair KeyPair) (accessKeyID string, secretAccessKey string, err error) {
	kp := string(keyPair)
	if len(kp) == 0 {
		return "", "", errors.New("missing access key keyPair")
	}
	keys := strings.Split(kp, ":")
	if len(keys) != 2 {
		return "", "", errors.New("invalid key pair format")
	}
	if len(keys[0]) == 0 {
		return "", "", errors.New("missing access key id")
	}
	if len(keys[1]) == 0 {
		return "", "", errors.New("missing secret access key")
	}
	return keys[0], keys[1], nil
}
