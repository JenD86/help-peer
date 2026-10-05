package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"regexp"
	"strings"
	"time"
)

// NotifyRequest is the JSON body for the notify API.
type NotifyRequest struct {
	TransferID   string   `json:"transfer_id"`
	ManifestHash string   `json:"manifest_hash"`
	Code         string   `json:"code"`
	Recipients   []string `json:"recipients"` // emails and/or usernames ("alice" or "@alice")
}

const maxRecipientsPerRequest = 20

// Transfer codes are six lowercase words joined by '-'. Anything else is
// rejected so this endpoint can't be used to email arbitrary text.
var codeRe = regexp.MustCompile(`^[a-z]+(-[a-z]+){5}$`)

// notifyHandler tells recipients about a transfer. Email addresses get the
// code by email; usernames get it in their inbox on this site plus an email
// alert that doesn't include it.
func (s *Server) notifyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	senderID, ok := s.getUserID(req)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body NotifyRequest
	req.Body = http.MaxBytesReader(w, req.Body, 64*1024)
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if !codeRe.MatchString(body.Code) {
		writeError(w, http.StatusBadRequest, "invalid transfer code")
		return
	}
	if !isHexHash(body.ManifestHash) {
		writeError(w, http.StatusBadRequest, "invalid manifest hash")
		return
	}
	if len(body.Recipients) == 0 || len(body.Recipients) > maxRecipientsPerRequest {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("between 1 and %d recipients required", maxRecipientsPerRequest))
		return
	}

	// Sort recipients into email addresses and usernames, refusing the
	// whole request if any is invalid so nobody gets a partial send.
	var emails []string
	inboxTo := map[string]string{} // username -> user ID
	var bad []string
	for _, r := range body.Recipients {
		r = strings.TrimSpace(r)
		if strings.Contains(strings.TrimPrefix(r, "@"), "@") {
			if !isValidEmail(r) {
				bad = append(bad, r)
				continue
			}
			emails = append(emails, r)
			continue
		}
		name := normalizeUsername(r)
		uid, ok := s.db.UserIDForUsername(name)
		if !ok {
			bad = append(bad, r)
			continue
		}
		inboxTo[name] = uid
	}
	if len(bad) > 0 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown recipients: %s", strings.Join(bad, ", ")))
		return
	}

	// Only the sender of a transfer they registered here can send
	// notifications about it, the transfer must really exist on the relay,
	// and only so many go out per hour.
	record, ok := s.db.GetTransfer(body.TransferID)
	if !ok || record.SenderID != senderID {
		writeError(w, http.StatusNotFound, "transfer not found")
		return
	}
	switch s.manifestExists(body.ManifestHash) {
	case existsNo:
		writeError(w, http.StatusNotFound, "transfer not found on the relay")
		return
	case existsUnknown:
		writeError(w, http.StatusBadGateway, "relay unavailable")
		return
	}
	if !s.notifyLimit.Allow(senderID, len(body.Recipients)) {
		writeError(w, http.StatusTooManyRequests, "notification limit reached, try again later")
		return
	}

	s.db.SetRecipients(record.ID, senderID, body.Recipients)

	sender, _ := s.db.GetUser(senderID)
	senderName := sender.Username
	if senderName == "" {
		senderName = sender.Email
	}

	sent, inboxed := 0, 0
	errors := []string{}

	for name, uid := range inboxTo {
		recipient, _ := s.db.GetUser(uid)
		s.db.AddInboxItem(&InboxItem{
			ID:             generateToken(16),
			RecipientID:    uid,
			SenderID:       senderID,
			SenderUsername: sender.Username,
			TransferName:   record.TransferName,
			Message:        record.Message,
			Files:          record.Files,
			TotalBytes:     record.TotalBytes,
			Code:           body.Code,
			ManifestHash:   body.ManifestHash,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(inboxTTL),
		})
		inboxed++
		if recipient.Email == "" {
			// No email on file; the inbox item is the only notification.
			continue
		}
		if s.smtpConfig.Host == "" {
			log.Printf("[DEV] Inbox alert to %s (@%s): transfer '%s' from %s, message: %q", recipient.Email, name, record.TransferName, senderName, record.Message)
			continue
		}
		if err := sendInboxAlertEmail(s.smtpConfig, recipient.Email, s.auth.baseURL, senderName, record.TransferName, record.Message, record.Files, record.TotalBytes); err != nil {
			log.Printf("Failed to send inbox alert to %s: %v", recipient.Email, err)
			errors = append(errors, fmt.Sprintf("alert email failed for @%s (the transfer is still in their inbox)", name))
		}
	}

	for _, recipient := range emails {
		if s.smtpConfig.Host == "" {
			log.Printf("[DEV] Email to %s: Transfer '%s' message: %q code: %s", recipient, record.TransferName, record.Message, body.Code)
			sent++
			continue
		}
		if err := sendTransferEmail(s.smtpConfig, recipient, body.Code, record.TransferName, record.Message, senderName, record.Files, record.TotalBytes); err != nil {
			log.Printf("Failed to send email to %s: %v", recipient, err)
			errors = append(errors, fmt.Sprintf("failed: %s", recipient))
			continue
		}
		sent++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"sent":    sent,
		"inboxed": inboxed,
		"errors":  errors,
	})
}

func (s *Server) historyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, ok := s.getUserID(req)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	transfers := s.db.GetTransfersByUserID(userID)
	if transfers == nil {
		transfers = []*TransferRecord{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"transfers": transfers,
	})
}

func sendMagicLinkEmail(smtpCfg *SMTPConfig, to, magicURL string) error {
	subject := "Help Peer — Login Link"
	body := fmt.Sprintf(`Hello,

Click the link below to log in to Help Peer:

  %s

This link expires in 15 minutes. If you didn't request this, you can safely ignore this email.

— Help Peer`, magicURL)

	return sendEmail(smtpCfg, to, subject, body)
}

func sendInboxAlertEmail(smtpCfg *SMTPConfig, to, baseURL, senderName, transferName, message string, files int, totalBytes int64) error {
	subject := fmt.Sprintf("Help Peer — %s sent you files", senderName)
	body := fmt.Sprintf(`Hello,

%s has sent you files via Help Peer.

  Transfer: %s
  Files: %d
  Size: %s
%s
They're waiting in your inbox (log in to see them):

  %s/inbox

The transfer expires in 24 hours.

— Help Peer`, senderName, transferName, files, formatBytes(totalBytes), emailMessageBlock(senderName, message), baseURL)

	return sendEmail(smtpCfg, to, subject, body)
}

func sendTransferEmail(smtpCfg *SMTPConfig, to, code, transferName, message, senderName string, files int, totalBytes int64) error {
	subject := fmt.Sprintf("Help Peer — %s sent you files", senderName)
	body := fmt.Sprintf(`Hello,

%s has sent you files via Help Peer.

  Transfer: %s
  Files: %d
  Size: %s
  Code: %s
%s
To download, go to Help Peer and enter the code above.

— Help Peer`, senderName, transferName, files, formatBytes(totalBytes), code, emailMessageBlock(senderName, message))

	return sendEmail(smtpCfg, to, subject, body)
}

// emailMessageBlock formats the sender's note for an email body, quoted so
// it's clearly the sender's words rather than Help Peer's.
func emailMessageBlock(sender, message string) string {
	if message == "" {
		return ""
	}
	lines := strings.Split(message, "\n")
	for i, l := range lines {
		lines[i] = "  > " + l
	}
	return fmt.Sprintf("\nMessage from %s:\n\n%s\n", sender, strings.Join(lines, "\n"))
}

func sendEmail(smtpCfg *SMTPConfig, to, subject, body string) error {
	from := smtpCfg.From
	if from == "" {
		from = smtpCfg.User
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body)

	addr := fmt.Sprintf("%s:%s", smtpCfg.Host, smtpCfg.Port)

	// Parse email addresses for auth
	fromAddr := mail.Address{}
	if parsed, err := mail.ParseAddress(from); err == nil {
		fromAddr = *parsed
	}

	auth := smtp.PlainAuth("", smtpCfg.User, smtpCfg.Password, smtpCfg.Host)

	// Gmail uses TLS on port 465, or STARTTLS on 587
	if smtpCfg.Port == "465" {
		return sendMailTLS(addr, auth, from, []string{to}, []byte(msg))
	}

	return smtp.SendMail(addr, auth, fromAddr.Address, []string{to}, []byte(msg))
}

func sendMailTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: strings.Split(addr, ":")[0],
	})
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, strings.Split(addr, ":")[0])
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer c.Quit()

	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("SMTP auth failed: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("RCPT TO failed: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close failed: %w", err)
	}
	return nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

