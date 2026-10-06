package main

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// readLinkEmail parses a message from buildLinkEmail and returns its subject
// and its text and HTML parts (already decoded).
func readLinkEmail(t *testing.T, raw []byte) (subject, text, html string) {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	subject, err = new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q (%v)", mt, err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var kinds []string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(p) // the reader decodes quoted-printable
		ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		kinds = append(kinds, ct)
		switch ct {
		case "text/plain":
			text = string(data)
		case "text/html":
			html = string(data)
		}
	}
	if len(kinds) != 2 || kinds[0] != "text/plain" || kinds[1] != "text/html" {
		t.Fatalf("parts are %v, want plain text first and HTML last", kinds)
	}
	return subject, text, html
}

func TestLinkEmailHasTextAndHTMLWithTheURL(t *testing.T) {
	const url = "https://help-peer.example/verify?token=abc123DEF456"
	raw, err := buildLinkEmail("Help Peer <noreply@example.com>", "me@example.com", "mallory", "", url, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	subject, text, html := readLinkEmail(t, raw)

	if subject != "Help Peer — Confirm your email address" {
		t.Fatalf("subject %q", subject)
	}
	// It says what the click does and which account asked.
	for _, part := range []string{text, html} {
		if !strings.Contains(part, "link this email address") || !strings.Contains(part, "@mallory") {
			t.Fatalf("a part does not name the account or the action:\n%s", part)
		}
		if strings.Contains(strings.ToLower(part), "log in") {
			t.Fatalf("it must not read like a login email:\n%s", part)
		}
		if !strings.Contains(part, "15 minutes") {
			t.Fatalf("expiry missing or not following magicLinkTTL:\n%s", part)
		}
	}
	// The URL is in both: as a button and as plain text for when the button fails.
	if !strings.Contains(text, url) {
		t.Fatalf("text part lacks the URL:\n%s", text)
	}
	if strings.Count(html, url) != 3 { // button href, visible link href, visible link text
		t.Fatalf("HTML should carry the URL as button, link and text, found %d times:\n%s", strings.Count(html, url), html)
	}
	if !strings.Contains(html, "Button not working?") {
		t.Fatal("HTML lacks the fallback hint")
	}
}

func TestLinkEmailEscapesWhatItInserts(t *testing.T) {
	raw, err := buildLinkEmail("a@example.com", "b@example.com", `x<script>alert(1)</script>&"`, "", "https://h.example/verify?token=t&x=<y>", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, _, html := readLinkEmail(t, raw)
	if strings.Contains(html, "<script>") || strings.Contains(html, "<y>") {
		t.Fatalf("markup got through:\n%s", html)
	}
}

func TestLinkEmailWithoutUsername(t *testing.T) {
	raw, _ := buildLinkEmail("a@example.com", "b@example.com", "", "", "https://h.example/verify?token=t", time.Now())
	_, text, html := readLinkEmail(t, raw)
	for _, part := range []string{text, html} {
		if !strings.Contains(part, "a Help Peer account") || strings.Contains(part, "@") {
			t.Fatalf("unexpected wording without a username:\n%s", part)
		}
	}
}

func TestLinkEmailRefusesHeaderInjection(t *testing.T) {
	if _, err := buildLinkEmail("a@example.com", "b@example.com\r\nBcc: evil@example.com", "x", "", "https://h.example/", time.Now()); err == nil {
		t.Fatal("a recipient containing a line break was accepted")
	}
}

func TestLoginEmailHasButtonAndFallbackURL(t *testing.T) {
	const url = "https://help-peer.example/verify?token=LOGINtoken123"
	raw, err := buildLoginEmail("Help Peer <noreply@example.com>", "me@example.com", url, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	subject, text, html := readLinkEmail(t, raw)
	if subject != "Help Peer — Login Link" {
		t.Fatalf("subject %q", subject)
	}
	if !strings.Contains(text, url) || strings.Count(html, url) != 3 {
		t.Fatalf("the URL must be in the text part and three times in the HTML (button, link, text):\n%s\n%s", text, html)
	}
	for _, want := range []string{"log in to Help Peer", "15 minutes"} {
		if !strings.Contains(text, want) || !strings.Contains(html, want) {
			t.Fatalf("%q missing from a part", want)
		}
	}
	if !strings.Contains(html, ">Log in</a>") || !strings.Contains(html, "Button not working?") {
		t.Fatalf("HTML lacks the button or the fallback hint:\n%s", html)
	}
}

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"joedhitya@kip.pro": "j***@kip.pro",
		"a@b.co":            "*@b.co",
		"ab@b.co":           "a***@b.co",
		"Zoë@example.com":   "Z***@example.com",
		"no-at-sign":        "",
		"@example.com":      "",
		"user@":             "",
		"":                  "",
	}
	for in, want := range cases {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChangeEmailWordingNamesTheOldAddressMasked(t *testing.T) {
	raw, err := buildLinkEmail("a@example.com", "new@example.com", "mallory", "joedhitya@kip.pro", "https://h.example/verify?token=t", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, text, html := readLinkEmail(t, raw)
	for _, part := range []string{text, html} {
		if !strings.Contains(part, "change the email address of the Help Peer account @mallory (currently j***@kip.pro)") {
			t.Fatalf("a part does not describe the change:\n%s", part)
		}
		if strings.Contains(part, "joedhitya") {
			t.Fatalf("the old address is not masked:\n%s", part)
		}
		if !strings.Contains(part, "nothing will be changed") || strings.Contains(part, "nothing will be linked") {
			t.Fatalf("wrong closing sentence:\n%s", part)
		}
	}
}

func TestLinkWordingStaysForAccountsWithoutEmail(t *testing.T) {
	raw, _ := buildLinkEmail("a@example.com", "b@example.com", "mallory", "", "https://h.example/verify?token=t", time.Now())
	_, text, _ := readLinkEmail(t, raw)
	if !strings.Contains(text, "link this email address to the Help Peer account @mallory.") || !strings.Contains(text, "nothing will be linked") {
		t.Fatalf("unexpected wording:\n%s", text)
	}
	if strings.Contains(text, "currently") {
		t.Fatal("an account without an email must not mention a current address")
	}
}

func TestSenderWithoutUsernameIsShownMasked(t *testing.T) {
	cases := []struct {
		name        string
		user        User
		wantShort   string
		wantLong    string
		mustNotShow string
	}{
		{"username", User{Username: "alice", Email: "alice@gmail.com"}, "alice", "alice", "alice@gmail.com"},
		{"email only", User{Email: "alice@gmail.com"}, "Someone", "Someone (a***@gmail.com)", "alice@gmail.com"},
		{"neither", User{}, "Someone", "Someone", "@"},
	}
	for _, c := range cases {
		got := senderDisplay(c.user)
		if got.Short != c.wantShort || got.Long != c.wantLong {
			t.Errorf("%s: got %+v", c.name, got)
		}
		for _, text := range []string{got.Short, got.Long} {
			if strings.Contains(text, c.mustNotShow) {
				t.Errorf("%s: %q reveals %q", c.name, text, c.mustNotShow)
			}
		}
	}
}

func notificationEmails(from senderInfo, transferName, message string) map[string]emailContent {
	return map[string]emailContent{
		"inbox alert": inboxAlertContent("https://h.example", from, transferName, message, 3, 1234),
		"transfer":    transferEmailContent("https://h.example", "orbit-velvet-zoom-candle-harbor-ember", transferName, message, from, 3, 1234),
	}
}

func TestNotificationEmailsNeverContainTheSendersFullAddress(t *testing.T) {
	from := senderDisplay(User{Email: "alice@gmail.com"})
	for name, c := range notificationEmails(from, "weights", "here you go") {
		raw, err := buildEmail("a@example.com", "b@example.com", c, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		subject, text, html := readLinkEmail(t, raw)
		if subject != "Help Peer — Someone sent you files" {
			t.Fatalf("%s: subject %q", name, subject)
		}
		for _, part := range []string{subject, text, html} {
			if strings.Contains(part, "alice@gmail.com") {
				t.Fatalf("%s shows the full address:\n%s", name, part)
			}
		}
		for _, part := range []string{text, html} {
			for _, want := range []string{"Someone (a***@gmail.com) has sent you files", "Message from Someone (a***@gmail.com):", "here you go", "weights", "1.2 KB"} {
				if !strings.Contains(part, want) {
					t.Fatalf("%s: %q missing from\n%s", name, want, part)
				}
			}
		}
	}
}

func TestNotificationEmailsHaveButtonAndFallbackURL(t *testing.T) {
	from := senderDisplay(User{Username: "alice"})
	emails := notificationEmails(from, "weights", "")
	want := map[string]struct{ button, url string }{
		"inbox alert": {">Open inbox</a>", "https://h.example/inbox"},
		"transfer":    {">Open Help Peer</a>", "https://h.example/download"},
	}
	for name, c := range emails {
		raw, _ := buildEmail("a@example.com", "b@example.com", c, time.Now())
		subject, text, html := readLinkEmail(t, raw)
		if subject != "Help Peer — alice sent you files" {
			t.Fatalf("%s: subject %q", name, subject)
		}
		w := want[name]
		if !strings.Contains(html, w.button) || !strings.Contains(html, "Button not working?") {
			t.Fatalf("%s: HTML lacks the button or the fallback hint:\n%s", name, html)
		}
		if !strings.Contains(text, w.url) || strings.Count(html, w.url) != 3 {
			t.Fatalf("%s: the URL must be in the text and three times in the HTML:\n%s\n%s", name, text, html)
		}
		if !strings.Contains(text, "24 hours") || !strings.Contains(html, "24 hours") {
			t.Fatalf("%s: expiry missing", name)
		}
	}
}

func TestTransferEmailShowsTheCodeInBothParts(t *testing.T) {
	from := senderDisplay(User{Username: "alice"})
	c := transferEmailContent("https://h.example", "orbit-velvet-zoom-candle-harbor-ember", "weights", "", from, 1, 10)
	raw, _ := buildEmail("a@example.com", "b@example.com", c, time.Now())
	_, text, html := readLinkEmail(t, raw)
	if !strings.Contains(text, "Code: orbit-velvet-zoom-candle-harbor-ember") {
		t.Fatalf("text lacks the code:\n%s", text)
	}
	if !strings.Contains(html, ">orbit-velvet-zoom-candle-harbor-ember</p>") || !strings.Contains(html, "Transfer code") {
		t.Fatalf("HTML lacks the code box:\n%s", html)
	}
	// An inbox alert has no code.
	inbox := inboxAlertContent("https://h.example", from, "weights", "", 1, 10)
	raw, _ = buildEmail("a@example.com", "b@example.com", inbox, time.Now())
	_, text, html = readLinkEmail(t, raw)
	if strings.Contains(text, "Code:") || strings.Contains(html, "Transfer code") {
		t.Fatal("an inbox alert must not show a code")
	}
}

func TestNotificationEmailsEscapeWhatTheSenderWrote(t *testing.T) {
	from := senderDisplay(User{Username: "alice"})
	for name, c := range notificationEmails(from, `<b>name</b>`, "hi <script>alert(1)</script>\nsecond line") {
		raw, _ := buildEmail("a@example.com", "b@example.com", c, time.Now())
		_, text, html := readLinkEmail(t, raw)
		if strings.Contains(html, "<script>") || strings.Contains(html, "<b>name</b>") {
			t.Fatalf("%s: markup got through:\n%s", name, html)
		}
		// The plain-text part keeps the words as they were written, quoted.
		if !strings.Contains(text, "  > second line") {
			t.Fatalf("%s: the message is not quoted line by line:\n%s", name, text)
		}
	}
}
