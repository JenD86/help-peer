package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const testShell = `<title>{{TITLE}}</title>
<meta name="description" content="{{DESCRIPTION}}" />
<link rel="canonical" href="{{PAGE_URL}}" />
<h1>{{H1}}</h1><p>{{LEAD}}</p>{{SITE_URL}}`

func TestSPAHandlerPerPageMeta(t *testing.T) {
	h := spaHandler(fstest.MapFS{"index.html": {Data: []byte(testShell)}}, "https://example.org")

	cases := []struct {
		path, title, h1, canonical string
	}{
		{"/", "Help Peer — Send &amp; Receive Files", "Help Peer: hand off large files", `href="https://example.org/"`},
		{"/upload", "Send Files — Help Peer", "Send files with a one-time code", `href="https://example.org/upload"`},
		{"/download", "Receive Files — Help Peer", "Receive files with a one-time code", `href="https://example.org/download"`},
		{"/inbox", "Help Peer — Send &amp; Receive Files", "Help Peer: hand off large files", `href="https://example.org/inbox"`},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
		body := rec.Body.String()
		for _, want := range []string{"<title>" + c.title + "</title>", c.h1, c.canonical} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: body missing %q:\n%s", c.path, want, body)
			}
		}
		if strings.Contains(body, "{{") {
			t.Errorf("%s: unfilled placeholder in body:\n%s", c.path, body)
		}
	}

	// Search results cut descriptions off past roughly 160 characters.
	for p, m := range pageMetas {
		if n := len([]rune(m.description)); n > 160 {
			t.Errorf("%s: description is %d characters, want at most 160", p, n)
		}
		if n := len([]rune(m.title)); n > 60 {
			t.Errorf("%s: title is %d characters, want at most 60", p, n)
		}
	}

	// The three public pages must not share a title or description.
	if pageMetas["/upload"].title == pageMetas["/"].title ||
		pageMetas["/download"].title == pageMetas["/upload"].title ||
		pageMetas["/upload"].description == pageMetas["/"].description ||
		pageMetas["/download"].description == pageMetas["/upload"].description {
		t.Error("public pages share a title or description")
	}
}
