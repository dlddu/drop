package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeReviewer map[string]string // token → "ns/name"

func (f fakeReviewer) Review(_ context.Context, token, audience string) (string, error) {
	if audience != "drop" {
		return "", ErrSAUnauthenticated
	}
	if sa, ok := f[token]; ok {
		return sa, nil
	}
	return "", ErrSAUnauthenticated
}

func TestSAExchange(t *testing.T) {
	e := newEnv(t)
	e.srv.cfg.SAAllow = []string{"homelab-k3s-mcp/homelab-k3s-mcp", "session-platform/session-mcp"}
	e.srv.cfg.PublicBaseURL = "https://drop.example"
	e.srv.cfg.SAAudience = "drop"
	e.srv.reviewer = fakeReviewer{"mcp-jwt": "homelab-k3s-mcp/homelab-k3s-mcp", "other-jwt": "default/default"}

	res, body := e.do("POST", "/api/v1/sa/token", strings.NewReader(`{"valid_minutes":30,"max_days":5,"label":"job"}`),
		map[string]string{"Authorization": "Bearer mcp-jwt", "Content-Type": "application/json"})
	if res.StatusCode != 201 {
		t.Fatalf("exchange: %d %s", res.StatusCode, body)
	}
	var out struct {
		T         string    `json:"token"`
		By        string    `json:"created_by"`
		Base      string    `json:"base_url"`
		MaxDays   int       `json:"max_days"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.T, "drk_") || out.By != "sa:homelab-k3s-mcp/homelab-k3s-mcp" || out.Base != "https://drop.example" || out.MaxDays != 5 {
		t.Fatalf("out %+v", out)
	}
	if got := out.ExpiresAt.Sub(e.now); got != 30*time.Minute {
		t.Fatalf("expiry %v", got)
	}

	// 받은 키로 업로드, 응답 주소는 공개 주소, 보관일 상한 5일
	id, pw := e.upload("/api/v1", map[string]string{"Authorization": "Bearer " + out.T, "Content-Type": "application/json"},
		map[string]any{"files": files([2]any{"report.txt", 4}), "days": 5}, [][]byte{[]byte("data")}, 4)
	d, err := e.srv.store.Get(id, e.now)
	if err != nil || !strings.HasPrefix(d.CreatedBy, "apikey:sa:homelab-k3s-mcp/homelab-k3s-mcp") {
		t.Fatalf("drop %+v %v", d, err)
	}
	b, _ := json.Marshal(map[string]any{"files": files([2]any{"x", 1}), "days": 6})
	if res, _ := e.do("POST", "/api/v1/uploads", strings.NewReader(string(b)), map[string]string{"Authorization": "Bearer " + out.T}); res.StatusCode != 400 {
		t.Fatalf("days over sa max: %d", res.StatusCode)
	}

	// JSON 목록(Basic)
	res, body = e.do("GET", "/get/"+id, nil, map[string]string{"Authorization": basic(id, pw), "Accept": "application/json"})
	if res.StatusCode != 200 || !strings.Contains(string(body), `"report.txt"`) {
		t.Fatalf("json listing: %d %s", res.StatusCode, body)
	}

	// 만료되면 키를 못 쓴다
	e.now = e.now.Add(31 * time.Minute)
	if res, _ := e.do("GET", "/api/v1/drops", nil, map[string]string{"Authorization": "Bearer " + out.T}); res.StatusCode != 401 {
		t.Fatalf("expired key: %d", res.StatusCode)
	}

	hdr := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }
	if res, _ := e.do("POST", "/api/v1/sa/token", nil, hdr("other-jwt")); res.StatusCode != 403 {
		t.Fatalf("not allowed sa: %d", res.StatusCode)
	}
	if res, _ := e.do("POST", "/api/v1/sa/token", nil, hdr("forged")); res.StatusCode != 401 {
		t.Fatalf("bad token: %d", res.StatusCode)
	}
	if res, _ := e.do("POST", "/api/v1/sa/token", nil, nil); res.StatusCode != 401 {
		t.Fatalf("no token: %d", res.StatusCode)
	}
	if res, _ := e.do("POST", "/api/v1/sa/token", strings.NewReader(`{"valid_minutes":2000}`), hdr("mcp-jwt")); res.StatusCode != 400 {
		t.Fatalf("too long: %d", res.StatusCode)
	}
	// 기본 60분
	res, body = e.do("POST", "/api/v1/sa/token", nil, hdr("mcp-jwt"))
	json.Unmarshal(body, &out)
	if res.StatusCode != 201 || out.ExpiresAt.Sub(e.now) != time.Hour {
		t.Fatalf("default: %d %s", res.StatusCode, body)
	}
}

func TestSAExchangeDisabled(t *testing.T) {
	e := newEnv(t)
	res, _ := e.do("POST", "/api/v1/sa/token", nil, map[string]string{"Authorization": "Bearer x"})
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("disabled: %d", res.StatusCode)
	}
}

func TestSAFromReview(t *testing.T) {
	cases := []struct {
		auth bool
		aud  []string
		user string
		want string
	}{
		{true, []string{"drop"}, "system:serviceaccount:homelab-k3s-mcp:homelab-k3s-mcp", "homelab-k3s-mcp/homelab-k3s-mcp"},
		{false, []string{"drop"}, "system:serviceaccount:a:b", ""},
		{true, []string{"https://kubernetes.default.svc"}, "system:serviceaccount:a:b", ""},
		{true, []string{"drop"}, "alice", ""},
		{true, []string{"drop"}, "system:serviceaccount:a", ""},
	}
	for _, c := range cases {
		got, err := saFromReview(c.auth, c.aud, c.user, "drop")
		if got != c.want || (c.want == "" && err == nil) {
			t.Errorf("%+v → %q %v", c, got, err)
		}
	}
}
