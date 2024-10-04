package security

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

var mySigningKey = []byte("secret")

type JwtCustomClaims struct {
	FingerprintHash string `json:"fpt"`
	jwt.RegisteredClaims
}

func CreateJwt(fingerprintHash string) string {
	claims := JwtCustomClaims{
		fingerprintHash,
		jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    "test",
			Audience:  jwt.ClaimStrings{"test"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 60)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString(mySigningKey)
	return ss
}

func ValidateJwt(jwtString, fingerprintHash string) bool {
	token, err := jwt.ParseWithClaims(jwtString, &JwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})
	if err != nil {
		return false
	}
	if claims, ok := token.Claims.(*JwtCustomClaims); ok && token.Valid {
		return claims.FingerprintHash == fingerprintHash
	}
	return false
}
