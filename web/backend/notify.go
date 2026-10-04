package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// NotifyRequest is the JSON body for the notify API.
type NotifyRequest struct {
	Code        string   `json:"code"`
	TransferName string   `json:"transfer_name"`
	Recipients  []string `json:"recipients"`
	Files       int      `json:"files"`
	TotalBytes  int64    `json:"total_bytes"`
}

func (s *Server) notifyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	senderEmail, ok := s.getUserEmail(req)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body NotifyRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if body.Code == "" || len(body.Recipients) == 0 {
		writeError(w, http.StatusBadRequest, "code and recipients required")
		return
	}

	if s.smtpConfig.Host == "" {
		// Dev mode: log notifications
		for _, r := range body.Recipients {
			log.Printf("[DEV] Email to %s: Transfer '%s' code: %s", r, body.TransferName, body.Code)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "logged",
			"sent":     len(body.Recipients),
			"message":  "SMTP not configured — emails logged to console",
		})
		return
	}

	sent := 0
	var errors []string
	for _, recipient := range body.Recipients {
		if !isValidEmail(recipient) {
			errors = append(errors, fmt.Sprintf("invalid email: %s", recipient))
			continue
		}
		if err := sendTransferEmail(s.smtpConfig, recipient, body.Code, body.TransferName, senderEmail, body.Files, body.TotalBytes); err != nil {
			log.Printf("Failed to send email to %s: %v", recipient, err)
			errors = append(errors, fmt.Sprintf("failed: %s", recipient))
			continue
		}
		sent++
	}

	// Save transfer record
	s.db.SaveTransfer(&TransferRecord{
		Code:         body.Code,
		SenderEmail:  senderEmail,
		Recipients:   body.Recipients,
		TransferName: body.TransferName,
		Files:        body.Files,
		TotalBytes:   body.TotalBytes,
		CreatedAt:    time.Now(),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"sent":   sent,
		"errors": errors,
	})
}

func (s *Server) historyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	email, ok := s.getUserEmail(req)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	transfers := s.db.GetTransfersByEmail(email)
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

func sendTransferEmail(smtpCfg *SMTPConfig, to, code, transferName, senderEmail string, files int, totalBytes int64) error {
	subject := fmt.Sprintf("Help Peer — %s sent you files", senderEmail)
	body := fmt.Sprintf(`Hello,

%s has sent you files via Help Peer.

  Transfer: %s
  Files: %d
  Size: %s
  Code: %s

To download, go to Help Peer and enter the code above.

— Help Peer`, senderEmail, transferName, files, formatBytes(totalBytes), code)

	return sendEmail(smtpCfg, to, subject, body)
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

var _ = net.Dial
