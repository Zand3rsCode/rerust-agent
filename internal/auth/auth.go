// Package auth keeps the machine key (only its sha256) and a pending pairing in <state>/auth.json.
//
// Pairing: `rerust-agent pair` makes a one-time secret (valid PairMinutes) and prints a pairing code = the agent's
// certificate fingerprint + that secret. The panel checks the certificate against the fingerprint, then sends the
// secret with a new machine key (POST /agent/v1/pair). From then on only that key works; the secret is gone. A new
// pairing (moving the machine to another panel, a lost key) replaces the key only once it has completed.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
)

// PairMinutes is how long a pairing code works.
const PairMinutes = 60

// KeyPattern is the panel's machine key format (Node::KEY_PATTERN): rn_ + 48 characters.
var KeyPattern = regexp.MustCompile(`^rn_[A-Za-z0-9]{48}$`)

type data struct {
	KeyHash     string `json:"key_hash,omitempty"`
	PairHash    string `json:"pair_hash,omitempty"`
	PairExpires int64  `json:"pair_expires,omitempty"`
	PairedAt    int64  `json:"paired_at,omitempty"`
}

// Store is auth.json; the running agent re-reads it when it changed (a `rerust-agent pair` from the shell).
type Store struct {
	path  string
	mu    sync.Mutex
	d     data
	mtime time.Time
	ino   uint64 // every save renames a new file in: a new inode, also within one clock tick
}

func inode(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// Open reads (or starts) the store.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.reload(true); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) reload(force bool) error {
	info, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.d = data{}
			return nil
		}
		return err
	}
	if !force && info.ModTime().Equal(s.mtime) && inode(info) == s.ino {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var d data
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	s.d, s.mtime, s.ino = d, info.ModTime(), inode(info)
	return nil
}

func (s *Store) save() error {
	raw, _ := json.MarshalIndent(s.d, "", "  ")
	if err := config.WriteAtomic(s.path, raw, 0o600); err != nil {
		return err
	}
	if info, err := os.Stat(s.path); err == nil {
		s.mtime, s.ino = info.ModTime(), inode(info)
	}
	return nil
}

func hash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// KeyOK is true for the paired panel's key (constant-time compare of the hashes).
func (s *Store) KeyOK(key string) bool {
	if key == "" || len(key) > 200 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.reload(false)
	if s.d.KeyHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hash(key)), []byte(s.d.KeyHash)) == 1
}

// Paired tells whether a panel has paired.
func (s *Store) Paired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.reload(false)
	return s.d.KeyHash != ""
}

// Pending tells whether a pairing code is waiting.
func (s *Store) Pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.reload(false)
	return s.d.PairHash != "" && time.Now().Unix() < s.d.PairExpires
}

// ErrPaired: the machine already has a panel - a new pairing must be asked for explicitly (it replaces that panel).
var ErrPaired = errors.New("this machine is already paired with a panel - add --replace to pair it with a new one (the current key stops working once the new pairing completes)")

// NewPairing makes a one-time secret (replacing any earlier one) and returns it. On a paired machine only with
// replace.
func (s *Store) NewPairing(replace bool) (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := s.reload(true); err != nil {
		return "", err
	}
	if s.d.KeyHash != "" && !replace {
		return "", ErrPaired
	}
	s.d.PairHash = hash(secret)
	s.d.PairExpires = time.Now().Add(PairMinutes * time.Minute).Unix()
	return secret, s.save()
}

// lockFile: the `pair` command and the running agent both write auth.json - one at a time.
func (s *Store) lockFile() (func(), error) {
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// ErrPairing is a wrong, used or expired pairing secret.
var ErrPairing = errors.New("this pairing code is wrong, used or expired - make a new one on the machine: sudo -u rerust-agent /opt/rerust-agent/rerust-agent pair")

// Pair completes a pairing: the secret must match the pending one; key becomes the only accepted key.
func (s *Store) Pair(secret, key string) error {
	if !KeyPattern.MatchString(key) {
		return errors.New("not a machine key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.reload(true); err != nil {
		return err
	}
	if s.d.PairHash == "" || time.Now().Unix() >= s.d.PairExpires ||
		subtle.ConstantTimeCompare([]byte(hash(secret)), []byte(s.d.PairHash)) != 1 {
		return ErrPairing
	}
	s.d.KeyHash = hash(key)
	s.d.PairHash, s.d.PairExpires = "", 0
	s.d.PairedAt = time.Now().Unix()
	return s.save()
}
