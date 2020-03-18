package secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"

	vault "github.com/hashicorp/vault/api"
)

// AES key fetched
const (
	nonceSize = aes.BlockSize
	macSize   = 32
	ckeySize  = 32
)

var (
	key    []byte
	prefix = "3DICC3It"
)

type Secret struct {
	Token  string
	Client *vault.Client
}

// Init secrets: cipherKey
// cipherKey is set from viper configuration
func Init(cipherKey string) {
	key = []byte(cipherKey)
}

// Create new secret client
func New(token, addr string) (*Secret, error) {
	client, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	client.SetAddress(addr)
	return &Secret{
		Client: client,
		Token:  token,
	}, nil
}

// GetFromVault Get secret from vault
func (secret *Secret) GetFromVault(s string) (string, error) {
	conf, err := secret.Client.Logical().Read(s)
	if err != nil {
		return "", err
	} else if conf == nil {
		log.Warning(context.Background(), "vault> no value found at %q", s)
		return "", nil
	}

	value, exists := conf.Data["data"]
	if !exists {
		log.Warning(context.Background(), "vault> no 'data' field found for %q (you must add a field with a key named data)", s)
		return "", nil
	}

	return fmt.Sprintf("%v", value), nil
}

// Decrypt data using aes+hmac algorithm
// Init() must be called before any decryption
func Decrypt(data []byte) ([]byte, error) {
	if !strings.HasPrefix(string(data), prefix) {
		return data, nil
	}
	data = []byte(strings.TrimPrefix(string(data), prefix))

	if key == nil {
		log.Error(context.TODO(), "Missing key, init failed?")
		return nil, sdk.WithStack(sdk.ErrSecretKeyFetchFailed)
	}

	if len(data) < (nonceSize + macSize) {
		log.Error(context.TODO(), "cannot decrypt secret, got invalid data")
		return nil, sdk.WithStack(sdk.ErrInvalidSecretFormat)
	}

	// Split actual data, hmac and nonce
	macStart := len(data) - macSize
	tag := data[macStart:]
	out := make([]byte, macStart-nonceSize)
	data = data[:macStart]
	// check hmac
	h := hmac.New(sha256.New, key[ckeySize:])
	h.Write(data)
	mac := h.Sum(nil)
	if !hmac.Equal(mac, tag) {
		return nil, sdk.WithStack(fmt.Errorf("invalid hmac"))
	}
	// uncipher data
	c, err := aes.NewCipher(key[:ckeySize])
	if err != nil {
		return nil, sdk.WithStack(fmt.Errorf("unable to create cypher block: %v", err))
	}
	ctr := cipher.NewCTR(c, data[:nonceSize])
	ctr.XORKeyStream(out, data[nonceSize:])
	return out, nil
}
