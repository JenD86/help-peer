package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

type Auth struct {
	db         *DB
	smtpConfig *SMTPConfig
	baseURL    string

	// Login emails go out from the operator's mail account, so cap how many
	// any one client or address can trigger.
	requestsPerIP    *rateLimiter
	requestsPerEmail *rateLimiter
}

func NewAuth(db *DB, smtp *SMTPConfig, baseURL string) *Auth {
	return &Auth{
		db:               db,
		smtpConfig:       smtp,
		baseURL:          baseURL,
		requestsPerIP:    newRateLimiter("login-ip", 10, 15*time.Minute),
		requestsPerEmail: newRateLimiter("login-email", 3, 15*time.Minute),
	}
}

func (a *Auth) authRequestHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if !isValidEmail(body.Email) {
		writeError(w, http.StatusBadRequest, "valid email required")
		return
	}

	if !a.requestsPerIP.Allow(clientIP(req), 1) || !a.requestsPerEmail.Allow(strings.ToLower(body.Email), 1) {
		writeError(w, http.StatusTooManyRequests, "too many login requests, try again later")
		return
	}

	link, err := a.db.CreateMagicLink(body.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create link")
		return
	}

	magicURL := fmt.Sprintf("%s/verify?token=%s", a.baseURL, link.Token)

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
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
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
		Secure:   strings.HasPrefix(a.baseURL, "https://"),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
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
		Secure:   strings.HasPrefix(a.baseURL, "https://"),
		SameSite: http.SameSiteStrictMode,
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

// isValidEmail accepts a bare address (no display name), which also rules
// out CR/LF and anything else that could inject email headers.
func isValidEmail(email string) bool {
	if email == "" || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && strings.Contains(email, "@")
}
