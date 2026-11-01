package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

// saExchange 는 허용된 서비스 계정에 짧게 쓰는 API 키를 내준다. 받은 키는 서비스 계정 API
// (/api/v1/drops, /api/v1/uploads)에 그대로 쓴다 — 파일은 호출자가 직접 HTTP 로 올린다.
//
//	POST /api/v1/sa/token
//	Authorization: Bearer <projected ServiceAccount 토큰, audience SA_TOKEN_AUDIENCE>
//	{"valid_minutes": 60, "max_days": 30, "label": "..."}   (전부 선택)
//	→ 201 {"token","expires_at","max_days","created_by","base_url"}
func (s *Server) saExchange(w http.ResponseWriter, r *http.Request) {
	if s.reviewer == nil {
		writeErr(w, http.StatusServiceUnavailable, "서비스 계정 교환이 설정되지 않았습니다")
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	tok = strings.TrimSpace(tok)
	if !ok || tok == "" {
		writeErr(w, http.StatusUnauthorized, "Authorization: Bearer <서비스 계정 토큰> 이 필요합니다")
		return
	}
	var req struct {
		ValidMinutes int    `json:"valid_minutes"`
		MaxDays      int    `json:"max_days"`
		Label        string `json:"label"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, "요청 형식이 잘못되었습니다")
			return
		}
	}
	if req.ValidMinutes == 0 {
		req.ValidMinutes = 60
	}
	if req.ValidMinutes < 1 || req.ValidMinutes > 24*60 {
		writeErr(w, http.StatusBadRequest, "valid_minutes 는 1~1440 입니다")
		return
	}

	sa, err := s.reviewer.Review(r.Context(), tok, s.cfg.SAAudience)
	switch {
	case errors.Is(err, ErrSAUnauthenticated):
		writeErr(w, http.StatusUnauthorized, "유효하지 않은 서비스 계정 토큰입니다(audience "+s.cfg.SAAudience+")")
		return
	case err != nil:
		slog.Error("tokenreview", "err", err)
		writeErr(w, http.StatusBadGateway, "서비스 계정을 확인하지 못했습니다")
		return
	}
	if !slices.Contains(s.cfg.SAAllow, sa) {
		slog.Warn("service account not allowed", "sa", sa)
		writeErr(w, http.StatusForbidden, "허용되지 않은 서비스 계정입니다: "+sa)
		return
	}

	label := "sa:" + sa
	if l := strings.TrimSpace(req.Label); l != "" {
		label += " " + l
	}
	t, secret, err := s.store.CreateToken(TokenRequest{
		Kind: "apikey", Label: label, MaxDays: req.MaxDays, validFor: time.Duration(req.ValidMinutes) * time.Minute,
	}, "sa:"+sa, s.cfg.MaxDays, s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	base := s.cfg.PublicBaseURL
	if base == "" {
		base = s.baseURL(r)
	}
	slog.Info("service account token issued", "sa", sa, "id", t.ID, "expires", t.ExpiresAt)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": secret, "expires_at": t.ExpiresAt, "max_days": t.MaxDays, "created_by": t.CreatedBy, "base_url": base,
	})
}
