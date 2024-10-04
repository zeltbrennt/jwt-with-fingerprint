package routes

import (
	"encoding/json"
	"jwt-demo/dto"
	"jwt-demo/security"
	"log"
	"net/http"
	"strings"
)

func Login(w http.ResponseWriter, req *http.Request) {

	loginRequest := dto.LoginDto{}
	json.NewDecoder(req.Body).Decode(&loginRequest)
	if loginRequest.IsValid() {
		fingerprint := security.NewRandomFingerprint()
		// cookie /w raw fingerprint
		fptCookie := http.Cookie{
			Name:     "fingerprint",
			Value:    fingerprint.Raw,
			MaxAge:   3600,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			//Secure: true,
		}
		// jwt-token /w hash
		accessToken := dto.TokenDto{Token: security.CreateJwt(fingerprint.Hash)}
		http.SetCookie(w, &fptCookie)
		json.NewEncoder(w).Encode(accessToken)
		log.Printf("%s received credentials", loginRequest.Username)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("failed login attempt from %s", req.RemoteAddr)
	}
}

func Secret(w http.ResponseWriter, req *http.Request) {
	// token + cookie present?
	authHeader := req.Header.Get("Authorization")
	cookie, err := req.Cookie("fingerprint")
	if authHeader == "" || err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("secret request denied")
		return
	}
	// prepare token and cookie
	fingerprint := security.GetFingerprintFromCookie(cookie)
	token, _ := strings.CutPrefix(authHeader, "Bearer ")
	// check
	if !security.ValidateJwt(token, fingerprint.Hash) {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("secret request denied")
		return
	}
	secret := dto.SecretDto{Name: "Secret Value of Pi", Value: "3"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
	log.Printf("secret request granted")
}
