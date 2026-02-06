package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	tokenBytes      = 32 // 256-bit session token
	idleTimeout     = 30 * time.Minute
	absoluteTimeout = 8 * time.Hour
	cleanupInterval = 1 * time.Minute
)

// Session holds per-user state keyed by session token.
type Session struct {
	Username      string
	EncryptedPass []byte
	CreatedAt     time.Time
	LastAccess    time.Time
}

// SessionStore is an in-memory, mutex-protected map of token → Session.
// A random AES-256-GCM key is generated at construction time; it never
// leaves process memory and is lost on restart (invalidating all sessions).
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	aead     cipher.AEAD
}

// NewSessionStore creates a store with a random encryption key and
// starts a background goroutine that removes expired sessions.
func NewSessionStore() (*SessionStore, error) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	s := &SessionStore{
		sessions: make(map[string]*Session),
		aead:     aead,
	}
	go s.cleanup()
	return s, nil
}

// Create generates a new session after successful authentication.
// It returns the opaque session token to be stored in a cookie.
func (s *SessionStore) Create(username, password string) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	encrypted, err := s.encrypt([]byte(password))
	if err != nil {
		return "", err
	}

	now := time.Now()
	s.mu.Lock()
	s.sessions[token] = &Session{
		Username:      username,
		EncryptedPass: encrypted,
		CreatedAt:     now,
		LastAccess:    now,
	}
	s.mu.Unlock()

	return token, nil
}

// Lookup validates a token and returns the associated credentials.
// It also implements sliding and absolute expiry.
func (s *SessionStore) Lookup(token string) (username, password string, ok bool) {
	s.mu.RLock()
	sess, exists := s.sessions[token]
	s.mu.RUnlock()

	if !exists {
		return "", "", false
	}

	now := time.Now()
	if now.Sub(sess.LastAccess) > idleTimeout || now.Sub(sess.CreatedAt) > absoluteTimeout {
		s.Delete(token)
		return "", "", false
	}

	s.mu.Lock()
	sess.LastAccess = now
	s.mu.Unlock()

	pass, err := s.decrypt(sess.EncryptedPass)
	if err != nil {
		return "", "", false
	}

	return sess.Username, string(pass), true
}

// Delete removes a session (logout or expiry).
func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// cleanup runs in its own goroutine and periodically removes expired sessions.
func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for token, sess := range s.sessions {
			if now.Sub(sess.LastAccess) > idleTimeout || now.Sub(sess.CreatedAt) > absoluteTimeout {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

func generateToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *SessionStore) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *SessionStore) decrypt(ciphertext []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return s.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}
