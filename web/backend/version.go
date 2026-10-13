package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
)

// commit is set at build time: -ldflags "-X main.commit=<sha>".
var commit = "unknown"

// versionHandler tells which commit is running and the SHA-256 of index.html
// as built, before {{SITE_URL}} and {{PAGE_URL}} are filled in.
func (s *Server) versionHandler(w http.ResponseWriter, req *http.Request) {
	shell, err := fs.ReadFile(s.static, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "index.html not found")
		return
	}
	sum := sha256.Sum256(shell)
	writeJSON(w, http.StatusOK, map[string]string{
		"commit":       commit,
		"index_sha256": hex.EncodeToString(sum[:]),
	})
}
