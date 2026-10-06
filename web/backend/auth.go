package main

import (
	"encoding/json"
	"errors"
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

	// Login and confirmation emails go out from the operator's mail account,
	// so every way of triggering one is capped. Each feature has its own
	// budget, so using one does not use up another, and the budgets that are
	// about an address are keyed by the requester too: someone who keeps
	// asking for emails to your address only uses up their own allowance.
	loginPerIP   *rateLimiter // log-in link requests per client
	loginPerPair *rateLimiter // ... per client and address
	signupPerIP  *rateLimiter // new accounts per client
	linkPerIP    *rateLimiter // "link email" requests per client
	linkPerUser  *rateLimiter // ... per account
	linkPerPair  *rateLimiter // ... per client and address
	emailTotal   *rateLimiter // all emails to one address, from anyone
}

func NewAuth(db *DB, smtp *SMTPConfig, baseURL string) *Auth {
	return &Auth{
		db:           db,
		smtpConfig:   smtp,
		baseURL:      baseURL,
		loginPerIP:   newRateLimiter("login-ip", 10, 15*time.Minute),
		loginPerPair: newRateLimiter("login-ip-email", 3, 15*time.Minute),
		signupPerIP:  newRateLimiter("signup-ip", 10, time.Hour),
		linkPerIP:    newRateLimiter("link-ip", 10, 15*time.Minute),
		linkPerUser:  newRateLimiter("link-user", 5, time.Hour),
		linkPerPair:  newRateLimiter("link-ip-email", 3, 15*time.Minute),
		emailTotal:   newRateLimiter("email-total", 10, time.Hour),
	}
}

// limiters lists the budgets, so their state is saved across restarts.
func (a *Auth) limiters() []*rateLimiter {
	return []*rateLimiter{
		a.loginPerIP, a.loginPerPair, a.signupPerIP,
		a.linkPerIP, a.linkPerUser, a.linkPerPair, a.emailTotal,
	}
}

// pairKey identifies one client asking about one address.
func pairKey(ip, email string) string {
	return ip + "|" + strings.ToLower(email)
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

	ip := clientIP(req)
	if !a.loginPerIP.Allow(ip, 1) ||
		!a.loginPerPair.Allow(pairKey(ip, body.Email), 1) ||
		!a.emailTotal.Allow(strings.ToLower(body.Email), 1) {
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

	userID, err := a.db.VerifyMagicLink(body.Token)
	if errors.Is(err, errEmailTaken) {
		writeError(w, http.StatusConflict, "That email address is already in use.")
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired link")
		return
	}

	sessionToken := a.db.CreateSession(userID)

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
	})
}

// authSignupHandler creates an account with just a username (no email).
// The user can link an email later via /api/auth/link-email.
func (a *Auth) authSignupHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	username := normalizeUsername(body.Username)
	if username == "" || !usernameRe.MatchString(username) || reservedUsernames[username] {
		writeError(w, http.StatusBadRequest, errUsernameInvalid.Error())
		return
	}

	if !a.signupPerIP.Allow(clientIP(req), 1) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again later")
		return
	}

	u := a.db.CreateUser()
	if err := a.db.SetProfile(u.ID, username, false); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	sessionToken := a.db.CreateSession(u.ID)

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
	})
}

// authLinkEmailHandler sends a magic link to verify and link an email to the
// currently logged-in user's account.
func (a *Auth) authLinkEmailHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cookie, err := req.Cookie("helppeer_session")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "log in to link an email")
		return
	}
	userID, ok := a.db.GetSession(cookie.Value)
	if !ok {
		writeError(w, http.StatusUnauthorized, "log in to link an email")
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

	// The client and account limits come first, then the "already in use"
	// check, then the limits that are about this address. Answering now
	// spares the user a pointless email, and probing an address that belongs
	// to someone else must not use up that person's allowance.
	ip := clientIP(req)
	if !a.linkPerIP.Allow(ip, 1) || !a.linkPerUser.Allow(userID, 1) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again later")
		return
	}
	if owner, taken := a.db.EmailOwner(body.Email); taken {
		if owner != userID {
			writeError(w, http.StatusConflict, "That email address is already in use.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "linked",
			"message": "That email address is already linked to your account.",
		})
		return
	}
	if !a.linkPerPair.Allow(pairKey(ip, body.Email), 1) || !a.emailTotal.Allow(strings.ToLower(body.Email), 1) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again later")
		return
	}

	link, err := a.db.CreateMagicLinkForUser(body.Email, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create link")
		return
	}

	magicURL := fmt.Sprintf("%s/verify?token=%s", a.baseURL, link.Token)

	if a.smtpConfig.Host != "" {
		var account, currentEmail string
		if u, ok := a.db.GetUser(userID); ok {
			account, currentEmail = u.Username, u.Email
		}
		if err := sendLinkEmail(a.smtpConfig, body.Email, account, currentEmail, magicURL); err != nil {
			log.Printf("Failed to send email: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to send email")
			return
		}
	} else {
		log.Printf("Email link for %s: %s", body.Email, magicURL)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "sent",
		"message": "Check your email to confirm and link it to your account",
	})
}

// authUnlinkEmailHandler removes the email from the logged-in account.
func (a *Auth) authUnlinkEmailHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cookie, err := req.Cookie("helppeer_session")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "log in to change your email")
		return
	}
	userID, ok := a.db.GetSession(cookie.Value)
	if !ok {
		writeError(w, http.StatusUnauthorized, "log in to change your email")
		return
	}
	if err := a.db.RemoveEmail(userID); err != nil {
		if errors.Is(err, errNeedUsername) {
			writeError(w, http.StatusBadRequest, "Set a username before removing your email, so you can still log in.")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not remove the email")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

// isValidEmail accepts a bare address (no display name), which also rules
// out CR/LF and anything else that could inject email headers.
func isValidEmail(email string) bool {
	if email == "" || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && strings.Contains(email, "@")
}
