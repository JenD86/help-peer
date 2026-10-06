package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The node's identity is an Ed25519 key pair, created on first start and
// kept in its data directory. The public key is the node's ID: it appears
// in /health and signs every registration, heartbeat and deregistration,
// so only whoever holds this key can change or remove the node.

const nodeIDPrefix = "ed25519:"

func nodeID(pub ed25519.PublicKey) string {
	return nodeIDPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

// loadOrCreateKey reads the node key from path, creating it if missing.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not a valid node key (%d bytes)", path, len(data))
		}
		return ed25519.NewKeyFromSeed(data), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// Private: anyone with this file can impersonate the node.
	if err := os.WriteFile(path, priv.Seed(), 0600); err != nil {
		return nil, err
	}
	return priv, nil
}
