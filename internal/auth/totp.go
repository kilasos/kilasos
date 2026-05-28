package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

func generateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func totpURI(secret, username, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30",
		issuer, username, secret, issuer)
}

func validateTOTP(secret, code string) bool {
	t := time.Now().Unix() / 30
	for _, counter := range []int64{t - 1, t, t + 1} {
		if totpCode(secret, counter) == code {
			return true
		}
	}
	return false
}

func totpCode(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg) //nolint:errcheck
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0F
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7FFFFFFF
	return fmt.Sprintf("%06d", code%uint32(math.Pow10(6)))
}
