package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

type Fingerprint struct {
	Raw  string
	Hash string
}

func NewRandomFingerprint() Fingerprint {
	// generate fingerprint + hash
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	return generateFingerprint(randomBytes)
}

func GetFingerprintFromCookie(c *http.Cookie) Fingerprint {
	raw := make([]byte, 32)
	hex.Decode(raw, []byte(c.Value))
	return generateFingerprint(raw)
}

func generateFingerprint(b []byte) Fingerprint {
	sha := sha256.New()
	sha.Write(b)
	return Fingerprint{
		Raw:  hex.EncodeToString(b),
		Hash: hex.EncodeToString(sha.Sum(nil)),
	}
}
