package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

type Auth struct {
	db         *DB
	smtpConfig *SMTPConfig
}

func NewAuth(db *DB, smtp *SMTPConfig) *Auth {
	return &Auth{db: db, smtpConfig: smtp}
}

func (a *Auth) authRequestHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if body.Email == "" || !isValidEmail(body.Email) {
		writeError(w, http.StatusBadRequest, "valid email required")
		return
	}

	link, err := a.db.CreateMagicLink(body.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create link")
		return
	}

	baseURL := getBaseURL(req)
	magicURL := fmt.Sprintf("%s/verify?token=%s", baseURL, link.Token)

	if a.smtpConfig.Host != "" {
		if err := sendMagicLinkEmail(a.smtpConfig, body.Email, magicURL); err != nil {
			log.Printf("Failed to send email: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to send email")
			return
		}
	} else {
		log.Printf("Magic link for %s: %s", body.Email, magicURL)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "sent",
		"message": "Check your email for a login link",
	})
}

func (a *Auth) authVerifyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	email, err := a.db.VerifyMagicLink(body.Token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired link")
		return
	}

	sessionToken := a.db.CreateSession(email)

	http.SetCookie(w, &http.Cookie{
		Name:     "helppeer_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400 * 7,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"email":  email,
	})
}

func (a *Auth) authLogoutHandler(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("helppeer_session")
	if err == nil {
		a.db.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "helppeer_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *Auth) authMeHandler(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("helppeer_session")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	email, ok := a.db.GetSession(cookie.Value)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"email":        email,
	})
}

func (a *Auth) GetUserBySession(token string) (string, bool) {
	return a.db.GetSession(token)
}

func isValidEmail(email string) bool {
	parsed, err := url.Parse("mailto:" + email)
	if err != nil {
		return false
	}
	return parsed.Opaque != "" && containsStr(email, "@")
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func getBaseURL(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if h := req.Header.Get("X-Forwarded-Proto"); h != "" {
		scheme = h
	}
	return fmt.Sprintf("%s://%s", scheme, req.Host)
}

// Ensure crypto/rand is used
var _ = rand.Reader
