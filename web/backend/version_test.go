package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestVersionReportsCommitAndTemplateHash(t *testing.T) {
	old := commit
	commit = "abc123"
	t.Cleanup(func() { commit = old })

	e := newTestEnv(t)
	resp, err := http.Get(e.srv.URL + "/api/version")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	decode(t, resp, &out)

	// The hash is of index.html as built, not of the page with the
	// placeholders filled in.
	template := `<html>app shell <link rel="canonical" href="{{PAGE_URL}}"> <meta content="{{SITE_URL}}/og.jpg"></html>`
	sum := sha256.Sum256([]byte(template))
	if out["commit"] != "abc123" || out["index_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected version: %v", out)
	}
}
