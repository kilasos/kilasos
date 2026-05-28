package wol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

type Store struct {
	mu      sync.RWMutex
	path    string
	targets []Target
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(data) > 0 {
		json.Unmarshal(data, &s.targets) //nolint:errcheck
	}
	return s, nil
}

func (s *Store) List() []Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Target, len(s.targets))
	copy(out, s.targets)
	return out
}

func (s *Store) Add(name, mac string) (Target, error) {
	if name == "" || mac == "" {
		return Target{}, errors.New("name and mac are required")
	}
	if _, err := parseMac(mac); err != nil {
		return Target{}, fmt.Errorf("invalid MAC: %w", err)
	}
	t := Target{ID: genID(), Name: name, MAC: normaliseMac(mac)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = append(s.targets, t)
	if err := s.save(); err != nil {
		return Target{}, err
	}
	return t, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.targets {
		if t.ID == id {
			s.targets = append(s.targets[:i], s.targets[i+1:]...)
			return s.save()
		}
	}
	return errors.New("target not found")
}

func (s *Store) Wake(id string) error {
	s.mu.RLock()
	var mac string
	for _, t := range s.targets {
		if t.ID == id {
			mac = t.MAC
			break
		}
	}
	s.mu.RUnlock()
	if mac == "" {
		return errors.New("target not found")
	}
	return SendMagicPacket(mac)
}

func SendMagicPacket(mac string) error {
	hw, err := parseMac(mac)
	if err != nil {
		return err
	}
	// 6 bytes 0xFF + 16 repetitions of the 6-byte MAC = 102 bytes
	pkt := make([]byte, 102)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xFF
	}
	for i := 1; i <= 16; i++ {
		copy(pkt[i*6:], hw)
	}
	conn, err := net.Dial("udp", "255.255.255.255:9")
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(pkt)
	return err
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.targets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0644)
}

func parseMac(mac string) (net.HardwareAddr, error) {
	// normalise separators then parse
	clean := strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":")
	if !strings.Contains(clean, ":") && len(clean) == 12 {
		// no separator — insert colons
		b := make([]byte, 6)
		if _, err := hex.Decode(b, []byte(clean)); err != nil {
			return nil, err
		}
		return b, nil
	}
	hw, err := net.ParseMAC(clean)
	if err != nil {
		return nil, err
	}
	if len(hw) != 6 {
		return nil, errors.New("only 48-bit MACs are supported")
	}
	return hw, nil
}

func normaliseMac(mac string) string {
	hw, err := parseMac(mac)
	if err != nil {
		return mac
	}
	return hw.String()
}

func genID() string {
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
