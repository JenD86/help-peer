package main

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"
)

const (
	linkEmailSubject  = "Help Peer — Confirm your email address"
	loginEmailSubject = "Help Peer — Login Link"
)

// emailContent describes one message that is sent both as plain text and as
// HTML with a button. The URL is always shown in full as well, so there is a
// way forward when the button doesn't work.
type emailContent struct {
	Subject    string
	Title      string // heading of the HTML version
	Intro      string // optional paragraph shown before the rest
	Details    []emailDetail
	Code       string // optional transfer code, shown in a box
	NoteFrom   string // who wrote Note
	Note       string // optional message from a sender, shown as a quote
	HTMLAction string // sentence above the button
	TextAction string // sentence above the URL in the plain-text version
	Button     string
	URL        string
	Footer     string
}

// emailDetail is one "label: value" row, such as "Files: 3".
type emailDetail struct {
	Label, Value string
}

// emailHTML is the HTML part. html/template escapes everything it inserts, so
// no field (an account name, the URL) can add markup.
var emailHTML = htmltemplate.Must(htmltemplate.New("email").Parse(`<!doctype html>
<html>
<body style="margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:#1f2937;">
<div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;padding:28px;">
<h1 style="font-size:20px;margin:0 0 16px;">{{.Title}}</h1>
{{if .Intro}}<p style="margin:0 0 16px;line-height:1.5;">{{.Intro}}</p>
{{end}}{{if .Details}}<table role="presentation" style="margin:0 0 20px;font-size:14px;border-collapse:collapse;">{{range .Details}}<tr><td style="padding:2px 16px 2px 0;color:#6b7280;">{{.Label}}</td><td style="padding:2px 0;">{{.Value}}</td></tr>{{end}}</table>
{{end}}{{if .Code}}<p style="margin:0 0 6px;font-size:13px;color:#4b5563;">Transfer code</p>
<p style="margin:0 0 20px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:15px;background:#f3f4f6;border-radius:6px;padding:12px;word-break:break-all;">{{.Code}}</p>
{{end}}{{if .Note}}<p style="margin:0 0 6px;font-size:13px;color:#4b5563;">Message from {{.NoteFrom}}:</p>
<blockquote style="margin:0 0 20px;padding:4px 0 4px 12px;border-left:3px solid #d1d5db;color:#374151;white-space:pre-wrap;">{{.Note}}</blockquote>
{{end}}<p style="margin:0 0 20px;line-height:1.5;">{{.HTMLAction}}</p>
<p style="margin:0 0 24px;"><a href="{{.URL}}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:6px;font-weight:600;">{{.Button}}</a></p>
<p style="margin:0 0 8px;font-size:13px;color:#4b5563;">Button not working? Copy and paste this address into your browser:</p>
<p style="margin:0 0 20px;font-size:13px;word-break:break-all;"><a href="{{.URL}}" style="color:#4f46e5;">{{.URL}}</a></p>
<p style="margin:0;font-size:13px;color:#4b5563;line-height:1.5;">{{.Footer}}</p>
</div>
</body>
</html>
`))

func (c emailContent) text() string {
	var b strings.Builder
	b.WriteString("Hello,\n\n")
	if c.Intro != "" {
		b.WriteString(c.Intro + "\n\n")
	}
	if len(c.Details) > 0 || c.Code != "" {
		for _, d := range c.Details {
			b.WriteString("  " + d.Label + ": " + d.Value + "\n")
		}
		if c.Code != "" {
			b.WriteString("  Code: " + c.Code + "\n")
		}
		b.WriteString("\n")
	}
	if c.Note != "" {
		b.WriteString(strings.TrimPrefix(emailMessageBlock(c.NoteFrom, c.Note), "\n") + "\n")
	}
	b.WriteString(c.TextAction + "\n\n")
	b.WriteString("  " + c.URL + "\n\n")
	b.WriteString("If the link does not work, copy the whole address into your browser.\n\n")
	b.WriteString(c.Footer + "\n\n")
	b.WriteString("— Help Peer")
	return b.String()
}

// buildEmail returns the full message: headers and a multipart/alternative body
// with the plain text first and the HTML last (clients prefer the last part).
func buildEmail(from, to string, c emailContent, now time.Time) ([]byte, error) {
	if strings.ContainsAny(from+to, "\r\n") {
		return nil, fmt.Errorf("invalid address")
	}
	var html bytes.Buffer
	if err := emailHTML.Execute(&html, c); err != nil {
		return nil, err
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	parts := []struct{ contentType, content string }{
		{"text/plain; charset=UTF-8", c.text()},
		{"text/html; charset=UTF-8", html.String()},
	}
	for _, p := range parts {
		pw, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {p.contentType},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(pw)
		if _, err := qp.Write([]byte(p.content)); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", c.Subject))
	fmt.Fprintf(&msg, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&msg, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", mw.Boundary())
	msg.Write(body.Bytes())
	return msg.Bytes(), nil
}

func expiryMinutes() int { return int(magicLinkTTL.Minutes()) }

// maskEmail hides most of an address, "joedhitya@kip.pro" -> "j***@kip.pro", so
// a message can name the address being replaced without revealing it. It
// returns "" for anything that isn't a plain address.
func maskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 1 || at == len(addr)-1 {
		return ""
	}
	local, domain := addr[:at], addr[at+1:]
	r := []rune(local)
	if len(r) == 1 {
		return "*@" + domain
	}
	return string(r[0]) + "***@" + domain
}

// linkEmailContent: asks the owner of an address to confirm it for an account
// (account is a username and may be empty). currentEmail is the address the
// account has now; when it is set the message says the address is being
// changed, and names the old one in masked form.
func linkEmailContent(account, currentEmail, linkURL string) emailContent {
	who := "a Help Peer account"
	if account != "" {
		who = "the Help Peer account @" + account
	}
	intro := "Someone asked to link this email address to " + who + "."
	outcome := "linked"
	if masked := maskEmail(currentEmail); masked != "" {
		intro = "Someone asked to change the email address of " + who + " (currently " + masked + ") to this address."
		outcome = "changed"
	}
	return emailContent{
		Subject:    linkEmailSubject,
		Title:      "Confirm your email address",
		Intro:      intro,
		HTMLAction: "If that was you, confirm it with the button below.",
		TextAction: "If that was you, confirm it by opening this link:",
		Button:     "Confirm email",
		URL:        linkURL,
		Footer: fmt.Sprintf("This link expires in %d minutes. If you did not ask for this, ignore this email: nothing will be %s.",
			expiryMinutes(), outcome),
	}
}

// loginEmailContent: the sign-in link.
func loginEmailContent(loginURL string) emailContent {
	return emailContent{
		Subject:    loginEmailSubject,
		Title:      "Log in to Help Peer",
		HTMLAction: "Click the button below to log in to Help Peer.",
		TextAction: "Click the link below to log in to Help Peer:",
		Button:     "Log in",
		URL:        loginURL,
		Footer: fmt.Sprintf("This link expires in %d minutes. If you didn't request this, you can safely ignore this email.",
			expiryMinutes()),
	}
}

func buildLinkEmail(from, to, account, currentEmail, linkURL string, now time.Time) ([]byte, error) {
	return buildEmail(from, to, linkEmailContent(account, currentEmail, linkURL), now)
}

func buildLoginEmail(from, to, loginURL string, now time.Time) ([]byte, error) {
	return buildEmail(from, to, loginEmailContent(loginURL), now)
}

func sendContent(smtpCfg *SMTPConfig, to string, c emailContent) error {
	from := smtpFrom(smtpCfg)
	msg, err := buildEmail(from, to, c, time.Now())
	if err != nil {
		return err
	}
	return deliverEmail(smtpCfg, from, to, msg)
}

// sendLinkEmail asks the owner of an address to confirm linking it to an
// account (or replacing the account's current email with it).
func sendLinkEmail(smtpCfg *SMTPConfig, to, account, currentEmail, linkURL string) error {
	return sendContent(smtpCfg, to, linkEmailContent(account, currentEmail, linkURL))
}

// sendMagicLinkEmail sends the login link.
func sendMagicLinkEmail(smtpCfg *SMTPConfig, to, magicURL string) error {
	return sendContent(smtpCfg, to, loginEmailContent(magicURL))
}
