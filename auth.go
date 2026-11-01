package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	alnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	friendly = "abcdefghjkmnpqrstuvwxyz23456789" // 헷갈리는 i l o 0 1 제외
)

func randomString(n int, alphabet string) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

// ---- 비밀번호 ----

const pbkdf2Iter = 210_000 // OWASP 2023 권고(PBKDF2-HMAC-SHA256)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func verifyPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- 받기 쿠키 ----
// 값: <만료 unix>.<HMAC(secret, id|만료|비밀번호 해시)>. 비밀번호 해시를 섞으므로 같은 아이디가
// 새 보관함으로 다시 쓰이면 예전 쿠키는 저절로 무효가 된다.

const grantTTL = 2 * time.Hour

func grantCookieName(id string) string { return "drop_" + strings.ReplaceAll(id, "-", "_") }

func signGrant(secret []byte, d *Drop, exp time.Time) string {
	e := strconv.FormatInt(exp.Unix(), 10)
	return e + "." + grantMAC(secret, d, e)
}

func grantMAC(secret []byte, d *Drop, e string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(d.ID + "|" + e + "|" + d.PasswordHash))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func verifyGrant(secret []byte, d *Drop, val string, now time.Time) bool {
	e, mac, ok := strings.Cut(val, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(e, 10, 64)
	if err != nil || now.Unix() >= exp {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(grantMAC(secret, d, e)))
}

// ---- 무차별 대입 제한 ----
// 아이디마다 15분에 5번 틀리면 15분 잠근다. 아이디가 사람이 고른 쉬운 값일 수 있으니
// 비밀번호(6자 이상)와 이 제한이 함께 지킨다. 출발지 IP 별 제한도 둔다(여러 아이디 훑기 방지).

type Limiter struct {
	mu     sync.Mutex
	fails  map[string][]time.Time
	window time.Duration
	max    int
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{fails: map[string][]time.Time{}, window: window, max: max}
}

func (l *Limiter) prune(key string, now time.Time) []time.Time {
	ts := l.fails[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = ts
	}
	return ts
}

func (l *Limiter) Blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, now)) >= l.max
}

func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[key] = append(l.prune(key, now), now)
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

// Sweep 은 오래된 기록을 버려 메모리가 쌓이지 않게 한다.
func (l *Limiter) Sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.fails {
		l.prune(k, now)
	}
}
