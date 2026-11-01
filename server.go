package main

import (
	"archive/zip"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*.html web/static/*
var webFS embed.FS

// 경로 구성(Traefik IngressRoute 가 같은 경계로 나눈다 — flux-cd-apps/apps/drop):
//
//	/admin, /admin/api/*   관리자. Traefik 에서 Authelia forward-auth 뒤(Remote-User 헤더).
//	/get, /get/{id}/...    받기. 공개 — 아이디·비밀번호.
//	/u/{token}/...         임시 업로드 링크. 공개 — 링크 자체가 자격.
//	/api/v1/*              서비스 계정 API. 공개 — Bearer API 키.
//	/static/*              정적 파일. 공개.
//	/healthz               프로브 전용(공개 라우트 없음).
type Server struct {
	cfg     Config
	store   *Store
	secret  []byte
	idLimit *Limiter
	ipLimit *Limiter
	tmpl    *template.Template
	mux     *http.ServeMux
	now     func() time.Time
	// reviewer 는 SA_ALLOW 가 있고 파드 안일 때만 있다. 없으면 서비스 계정 교환은 503.
	reviewer TokenReviewer
}

type Principal struct {
	Name    string
	Via     string // admin | link | apikey
	TokenID string
	Hash    string // 토큰 해시(link 사용 횟수 차감용)
	MaxDays int
}

func NewServer(cfg Config, st *Store) (*Server, error) {
	secret, err := st.Secret()
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"bytes": humanBytes,
		"date":  func(t time.Time) string { return t.In(kst).Format("2006-01-02 15:04") },
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i + 1
			}
			return out
		},
	}).ParseFS(webFS, "web/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, store: st, secret: secret, tmpl: tmpl,
		idLimit: NewLimiter(5, 15*time.Minute),
		ipLimit: NewLimiter(30, 15*time.Minute),
		mux:     http.NewServeMux(),
		now:     time.Now,
	}
	if len(cfg.SAAllow) > 0 {
		if s.reviewer, err = newInClusterReviewer(); err != nil {
			return nil, err
		}
	}
	s.routes()
	return s, nil
}

var kst = time.FixedZone("KST", 9*60*60)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	m := s.mux
	static, _ := fs.Sub(webFS, "web/static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/get", http.StatusFound) })

	// 받기
	m.HandleFunc("GET /get", s.getForm)
	m.HandleFunc("POST /get", s.getLogin)
	m.HandleFunc("GET /get/{id}", s.getDrop)
	m.HandleFunc("GET /get/{id}/f/{n}", s.getFile)
	m.HandleFunc("GET /get/{id}/all.zip", s.getZip)

	// 업로드: 같은 핸들러를 세 가지 자격으로 건다.
	s.uploadRoutes("/admin/api", s.adminPrincipal, true)
	s.uploadRoutes("/u/{token}/api", s.linkPrincipal, true)
	s.uploadRoutes("/api/v1", s.apiPrincipal, false)

	// 임시 업로드 링크 화면
	m.HandleFunc("GET /u/{token}", s.linkPage)

	// 서비스 계정 API
	m.HandleFunc("POST /api/v1/drops", s.withAuth(s.apiPrincipal, false, s.apiSimpleUpload))
	m.HandleFunc("GET /api/v1/drops", s.withAuth(s.apiPrincipal, false, s.apiListOwn))
	m.HandleFunc("DELETE /api/v1/drops/{id}", s.withAuth(s.apiPrincipal, false, s.apiDeleteOwn))

	// 클러스터 안 서비스 계정 → 단기 API 키. 공개 라우트에서는 Traefik 이 이 경로를 막는다
	// (flux-cd-apps/apps/drop) — 클러스터 안 이름(drop-external)으로만 닿는다.
	m.HandleFunc("POST /api/v1/sa/token", s.saExchange)

	// 관리자
	m.HandleFunc("GET /admin", s.adminPage)
	m.HandleFunc("GET /admin/api/drops", s.withAuth(s.adminPrincipal, false, s.adminListDrops))
	m.HandleFunc("DELETE /admin/api/drops/{id}", s.withAuth(s.adminPrincipal, true, s.adminDeleteDrop))
	m.HandleFunc("GET /admin/api/tokens", s.withAuth(s.adminPrincipal, false, s.adminListTokens))
	m.HandleFunc("POST /admin/api/tokens", s.withAuth(s.adminPrincipal, true, s.adminCreateToken))
	m.HandleFunc("DELETE /admin/api/tokens/{tid}", s.withAuth(s.adminPrincipal, true, s.adminRevokeToken))
}

// ---- 자격 ----

type principalFunc func(r *http.Request) (*Principal, int, string)

// adminPrincipal 은 Authelia 가 넣은 Remote-User 를 믿는다. 이 헤더는 Traefik 의 forward-auth 가
// 덮어쓰고, 공개 라우트에서는 Traefik 이 지운다. 이 경로(/admin)는 forward-auth 라우트로만 들어온다.
func (s *Server) adminPrincipal(r *http.Request) (*Principal, int, string) {
	user := strings.TrimSpace(r.Header.Get("Remote-User"))
	if user == "" {
		return nil, http.StatusUnauthorized, "로그인이 필요합니다"
	}
	if len(s.cfg.AdminGroups) > 0 {
		ok := false
		for _, g := range strings.Split(r.Header.Get("Remote-Groups"), ",") {
			for _, want := range s.cfg.AdminGroups {
				if strings.TrimSpace(g) == want {
					ok = true
				}
			}
		}
		if !ok {
			return nil, http.StatusForbidden, "관리자 그룹이 아닙니다"
		}
	}
	return &Principal{Name: user, Via: "admin"}, 0, ""
}

func (s *Server) linkPrincipal(r *http.Request) (*Principal, int, string) {
	t, err := s.store.LookupToken(r.PathValue("token"), "link", s.now())
	if errors.Is(err, ErrTokenExpired) {
		return nil, http.StatusGone, "만료되었거나 모두 사용한 업로드 링크입니다"
	}
	if err != nil {
		return nil, http.StatusNotFound, "없는 업로드 링크입니다"
	}
	name := "link:" + t.ID
	if t.Label != "" {
		name = "link:" + t.Label
	}
	return &Principal{Name: name, Via: "link", TokenID: t.ID, Hash: t.Hash, MaxDays: t.MaxDays}, 0, ""
}

func (s *Server) apiPrincipal(r *http.Request) (*Principal, int, string) {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return nil, http.StatusUnauthorized, "Authorization: Bearer <API 키> 가 필요합니다"
	}
	t, err := s.store.LookupToken(strings.TrimSpace(tok), "apikey", s.now())
	if err != nil {
		return nil, http.StatusUnauthorized, "유효하지 않은 API 키입니다"
	}
	name := "apikey:" + t.ID
	if t.Label != "" {
		name = "apikey:" + t.Label
	}
	return &Principal{Name: name, Via: "apikey", TokenID: t.ID, Hash: t.Hash, MaxDays: t.MaxDays}, 0, ""
}

type authedHandler func(w http.ResponseWriter, r *http.Request, p *Principal)

// withAuth 는 자격을 확인한다. csrf 가 true 면 브라우저용 쓰기 요청에 X-Drop 헤더를 요구한다 —
// 사용자 지정 헤더는 다른 출처의 폼·단순 요청으로는 붙일 수 없다(CORS 를 열지 않는다).
func (s *Server) withAuth(pf principalFunc, csrf bool, h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, code, msg := pf(r)
		if p == nil {
			writeErr(w, code, msg)
			return
		}
		if csrf && r.Header.Get("X-Drop") != "1" {
			writeErr(w, http.StatusForbidden, "X-Drop 헤더가 필요합니다")
			return
		}
		h(w, r, p)
	}
}

// ---- 업로드(조각) ----
//
// Traefik websecure 의 readTimeout(기본 60초) 안에 큰 파일을 한 요청으로 올릴 수 없으므로
// 브라우저는 파일을 조각(CHUNK_BYTES)으로 나눠 올린다. 조각은 offset 으로 이어 붙이므로
// 실패하면 서버가 받은 위치부터 다시 보낼 수 있다.
//
//	POST {prefix}/uploads                               시작 → id·password·upload_key
//	PUT  {prefix}/uploads/{id}/{key}/files/{n}?offset=  조각
//	GET  {prefix}/uploads/{id}/{key}/files/{n}          받은 크기(이어 올리기용)
//	POST {prefix}/uploads/{id}/{key}/complete           완료 → 보관함 열림

func (s *Server) uploadRoutes(prefix string, pf principalFunc, csrf bool) {
	s.mux.HandleFunc("POST "+prefix+"/uploads", s.withAuth(pf, csrf, s.uploadInit))
	s.mux.HandleFunc("PUT "+prefix+"/uploads/{id}/{key}/files/{n}", s.withAuth(pf, csrf, s.uploadChunk))
	s.mux.HandleFunc("GET "+prefix+"/uploads/{id}/{key}/files/{n}", s.withAuth(pf, false, s.uploadStatus))
	s.mux.HandleFunc("POST "+prefix+"/uploads/{id}/{key}/complete", s.withAuth(pf, csrf, s.uploadComplete))
}

func (s *Server) limits() Limits {
	return Limits{
		MaxFileBytes: s.cfg.MaxFileBytes, MaxTotalBytes: s.cfg.MaxTotalBytes,
		MaxFiles: s.cfg.MaxFiles, MaxDays: s.cfg.MaxDays, DefaultDays: s.cfg.DefaultDays,
	}
}

type initResponse struct {
	ID         string     `json:"id"`
	Password   string     `json:"password"`
	UploadKey  string     `json:"upload_key"`
	Days       int        `json:"days"`
	ChunkBytes int64      `json:"chunk_bytes"`
	Files      []FileMeta `json:"files"`
}

func (s *Server) uploadInit(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req CreateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "요청 형식이 잘못되었습니다")
		return
	}
	d, pw, key, err := s.store.CreatePending(req, Creator{Name: p.Name, Via: p.Via, TokenID: p.TokenID, MaxDays: p.MaxDays}, s.limits(), s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	slog.Info("upload started", "id", d.ID, "by", p.Name, "files", len(d.Files), "bytes", d.TotalSize())
	writeJSON(w, http.StatusCreated, initResponse{
		ID: d.ID, Password: pw, UploadKey: key, Days: d.Days, ChunkBytes: s.cfg.ChunkBytes, Files: d.Files,
	})
}

func (s *Server) uploadChunk(w http.ResponseWriter, r *http.Request, p *Principal) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "없는 파일입니다")
		return
	}
	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 {
		writeErr(w, http.StatusBadRequest, "offset 이 필요합니다")
		return
	}
	if r.ContentLength > s.cfg.MaxChunkBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("조각은 %s까지입니다", humanBytes(s.cfg.MaxChunkBytes)))
		return
	}
	got, err := s.store.WriteChunk(r.PathValue("id"), r.PathValue("key"), n, offset, r.Body, s.cfg.MaxChunkBytes, s.now())
	if errors.Is(err, ErrOffset) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "offset 이 맞지 않습니다", "received": got})
		return
	}
	if err != nil {
		s.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": got})
}

func (s *Server) uploadStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "없는 파일입니다")
		return
	}
	d, err := s.store.pendingFor(r.PathValue("id"), r.PathValue("key"), s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	if n < 0 || n >= len(d.Files) {
		writeErr(w, http.StatusNotFound, "없는 파일입니다")
		return
	}
	got, err := s.store.Received(d.ID, n)
	if err != nil {
		s.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": got, "size": d.Files[n].Size})
}

func (s *Server) uploadComplete(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Via == "link" {
		// 링크 사용 횟수는 업로드가 끝날 때 차감한다(중간에 실패한 시도는 세지 않는다).
		if err := s.store.UseToken(p.Hash, s.now()); err != nil {
			writeErr(w, http.StatusGone, "만료되었거나 모두 사용한 업로드 링크입니다")
			return
		}
	}
	d, err := s.store.Complete(r.PathValue("id"), r.PathValue("key"), s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	slog.Info("upload completed", "id", d.ID, "by", p.Name, "expires", d.ExpiresAt)
	writeJSON(w, http.StatusOK, dropView(d, s.baseURL(r)))
}

// ---- 서비스 계정 API ----

// apiSimpleUpload 는 multipart 한 번으로 올린다(작은 파일용 — 큰 파일은 /api/v1/uploads 조각 API).
// 폼 필드: file(여러 개), id, password, days.
func (s *Server) apiSimpleUpload(w http.ResponseWriter, r *http.Request, p *Principal) {
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "multipart/form-data 가 필요합니다")
		return
	}
	// 파일 크기를 미리 알 수 없으므로 임시로 받은 뒤 보관함을 만든다. 필드는 파일보다 앞에 둔다.
	var req CreateRequest
	type part struct {
		name string
		path string
		size int64
	}
	var parts []part
	tmpDir, err := makeTempDir(s.cfg.DataDir)
	if err != nil {
		s.storeErr(w, err)
		return
	}
	defer removeAll(tmpDir)
	for {
		pt, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "multipart 를 읽지 못했습니다")
			return
		}
		switch pt.FormName() {
		case "id", "password", "days":
			b, _ := io.ReadAll(io.LimitReader(pt, 256))
			v := strings.TrimSpace(string(b))
			switch pt.FormName() {
			case "id":
				req.ID = v
			case "password":
				req.Password = v
			case "days":
				req.Days, _ = strconv.Atoi(v)
			}
		case "file":
			if len(parts) >= s.cfg.MaxFiles {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("파일은 한 번에 %d개까지입니다", s.cfg.MaxFiles))
				return
			}
			path, size, err := saveTemp(tmpDir, len(parts), pt, s.cfg.MaxFileBytes)
			if err != nil {
				writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
				return
			}
			parts = append(parts, part{name: pt.FileName(), path: path, size: size})
		}
		pt.Close()
	}
	for _, pt := range parts {
		req.Files = append(req.Files, FileMeta{Name: pt.name, Size: pt.size})
	}
	d, pw, key, err := s.store.CreatePending(req, Creator{Name: p.Name, Via: p.Via, TokenID: p.TokenID, MaxDays: p.MaxDays}, s.limits(), s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	for i, pt := range parts {
		if err := moveInto(pt.path, s.store.filePath(d.ID, i)); err != nil {
			s.store.Delete(d.ID)
			s.storeErr(w, err)
			return
		}
	}
	id := d.ID
	d, err = s.store.Complete(id, key, s.now())
	if err != nil {
		s.store.Delete(id)
		s.storeErr(w, err)
		return
	}
	v := dropView(d, s.baseURL(r))
	v.Password = pw
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) apiListOwn(w http.ResponseWriter, r *http.Request, p *Principal) {
	all, err := s.store.List(s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	out := []DropView{}
	for _, d := range all {
		if d.TokenID == p.TokenID && !d.Pending {
			out = append(out, dropView(d, s.baseURL(r)))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiDeleteOwn(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, err := s.store.readDrop(r.PathValue("id"))
	if err != nil || d.TokenID != p.TokenID {
		writeErr(w, http.StatusNotFound, "없는 보관함입니다")
		return
	}
	if err := s.store.Delete(d.ID); err != nil {
		s.storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- 관리자 ----

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	p, code, msg := s.adminPrincipal(r)
	if p == nil {
		s.page(w, code, "error.html", map[string]any{"Title": "접근 불가", "Message": msg})
		return
	}
	s.page(w, http.StatusOK, "admin.html", map[string]any{
		"Title": "drop 관리", "User": p.Name, "Upload": s.uploadPageData("/admin/api", s.cfg.MaxDays),
	})
}

func (s *Server) adminListDrops(w http.ResponseWriter, r *http.Request, p *Principal) {
	all, err := s.store.List(s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	out := []DropView{}
	var used int64
	for _, d := range all {
		used += d.TotalSize()
		out = append(out, dropView(d, s.baseURL(r)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"drops": out, "used_bytes": used, "max_total_bytes": s.cfg.MaxTotalBytes})
}

func (s *Server) adminDeleteDrop(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.store.Delete(r.PathValue("id")); err != nil {
		s.storeErr(w, err)
		return
	}
	slog.Info("drop deleted", "id", r.PathValue("id"), "by", p.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListTokens(w http.ResponseWriter, r *http.Request, p *Principal) {
	toks, err := s.store.ListTokens()
	if err != nil {
		s.storeErr(w, err)
		return
	}
	now := s.now()
	out := []map[string]any{}
	for _, t := range toks {
		out = append(out, map[string]any{
			"id": t.ID, "kind": t.Kind, "label": t.Label, "created_by": t.CreatedBy,
			"created_at": t.CreatedAt, "expires_at": t.ExpiresAt, "max_uses": t.MaxUses,
			"uses": t.Uses, "max_days": t.MaxDays, "revoked": t.Revoked, "usable": t.Usable(now),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminCreateToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req TokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "요청 형식이 잘못되었습니다")
		return
	}
	t, secret, err := s.store.CreateToken(req, p.Name, s.cfg.MaxDays, s.now())
	if err != nil {
		s.storeErr(w, err)
		return
	}
	resp := map[string]any{"id": t.ID, "kind": t.Kind, "secret": secret}
	if t.Kind == "link" {
		resp["url"] = s.baseURL(r) + "/u/" + secret
	}
	slog.Info("token created", "id", t.ID, "kind", t.Kind, "by", p.Name)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) adminRevokeToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.store.RevokeToken(r.PathValue("tid")); err != nil {
		s.storeErr(w, err)
		return
	}
	slog.Info("token revoked", "id", r.PathValue("tid"), "by", p.Name)
	w.WriteHeader(http.StatusNoContent)
}

// ---- 임시 업로드 링크 화면 ----

func (s *Server) linkPage(w http.ResponseWriter, r *http.Request) {
	p, code, msg := s.linkPrincipal(r)
	if p == nil {
		s.page(w, code, "error.html", map[string]any{"Title": "업로드 링크", "Message": msg})
		return
	}
	s.page(w, http.StatusOK, "upload.html", map[string]any{
		"Title": "파일 올리기", "Upload": s.uploadPageData("/u/"+url.PathEscape(r.PathValue("token"))+"/api", min(p.MaxDays, s.cfg.MaxDays)),
	})
}

type uploadPageData struct {
	API         string
	MaxDays     int
	DefaultDays int
	MaxFile     int64
	MaxFiles    int
}

func (s *Server) uploadPageData(api string, maxDays int) uploadPageData {
	return uploadPageData{API: api, MaxDays: maxDays, DefaultDays: min(s.cfg.DefaultDays, maxDays), MaxFile: s.cfg.MaxFileBytes, MaxFiles: s.cfg.MaxFiles}
}

// ---- 받기 ----

func clientIP(r *http.Request) string {
	// Traefik 은 바깥에서 온 X-Real-Ip/X-Forwarded-* 를 버리고 자기가 본 출발지로 채운다.
	if ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) getForm(w http.ResponseWriter, r *http.Request) {
	s.page(w, http.StatusOK, "get.html", map[string]any{"Title": "파일 받기", "ID": r.URL.Query().Get("id")})
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	id := strings.ToLower(strings.TrimSpace(r.PostFormValue("id")))
	pw := strings.TrimSpace(r.PostFormValue("password"))
	d, status, msg := s.authorize(r, id, pw)
	if d == nil {
		s.page(w, status, "get.html", map[string]any{"Title": "파일 받기", "ID": id, "Error": msg})
		return
	}
	exp := s.now().Add(grantTTL)
	http.SetCookie(w, &http.Cookie{
		Name: grantCookieName(d.ID), Value: signGrant(s.secret, d, exp), Path: "/get/" + d.ID,
		Expires: exp, HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/get/"+d.ID, http.StatusSeeOther)
}

// authorize 는 아이디·비밀번호를 확인한다. 실패 메시지는 아이디가 있는지 드러내지 않는다.
func (s *Server) authorize(r *http.Request, id, pw string) (*Drop, int, string) {
	now := s.now()
	ip := clientIP(r)
	if s.idLimit.Blocked(id, now) || s.ipLimit.Blocked(ip, now) {
		return nil, http.StatusTooManyRequests, "시도가 너무 많습니다. 15분 뒤에 다시 시도하세요."
	}
	d, err := s.store.Get(id, now)
	if err == nil && verifyPassword(d.PasswordHash, pw) {
		s.idLimit.Reset(id)
		return d, 0, ""
	}
	if err == nil {
		s.idLimit.Fail(id, now)
	}
	s.ipLimit.Fail(ip, now)
	return nil, http.StatusUnauthorized, "아이디 또는 비밀번호가 맞지 않거나, 보관 기간이 끝났습니다."
}

// grantedDrop 은 쿠키나 Basic 인증(curl -u 아이디:비밀번호)으로 받을 권한을 확인한다.
func (s *Server) grantedDrop(w http.ResponseWriter, r *http.Request) (*Drop, bool) {
	id := strings.ToLower(r.PathValue("id"))
	if u, pw, ok := r.BasicAuth(); ok {
		d, status, msg := s.authorize(r, strings.ToLower(u), pw)
		if d == nil || d.ID != id {
			if d != nil {
				status, msg = http.StatusUnauthorized, "아이디가 주소와 다릅니다"
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="drop"`)
			http.Error(w, msg, status)
			return nil, false
		}
		return d, true
	}
	d, err := s.store.Get(id, s.now())
	if err == nil {
		if c, cerr := r.Cookie(grantCookieName(id)); cerr == nil && verifyGrant(s.secret, d, c.Value, s.now()) {
			return d, true
		}
	}
	return nil, false
}

func (s *Server) getDrop(w http.ResponseWriter, r *http.Request) {
	d, ok := s.grantedDrop(w, r)
	if !ok {
		if r.Header.Get("Authorization") == "" {
			http.Redirect(w, r, "/get?id="+url.QueryEscape(r.PathValue("id")), http.StatusSeeOther)
		}
		return
	}
	// 스크립트·도구용: 파일 목록만 JSON 으로(내용은 /f/{n} 으로 따로 받는다).
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"id": d.ID, "files": d.Files, "bytes": d.TotalSize(), "expires_at": d.ExpiresAt,
		})
		return
	}
	s.page(w, http.StatusOK, "files.html", map[string]any{"Title": d.ID, "Drop": d})
}

func (s *Server) getFile(w http.ResponseWriter, r *http.Request) {
	d, ok := s.grantedDrop(w, r)
	if !ok {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "권한이 없습니다", http.StatusUnauthorized)
		}
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	f, ferr := s.store.OpenFile(d, n)
	if err != nil || ferr != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	name := d.Files[n].Name
	w.Header().Set("Content-Disposition", contentDisposition(name))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Header.Get("Range") == "" {
		s.store.RecordDownload(d.ID, s.now())
	}
	// ServeContent 가 Range(이어 받기)를 처리한다. 수정 시각은 비워 조건부 요청 혼선을 막는다.
	http.ServeContent(w, r, "", time.Time{}, f)
}

func (s *Server) getZip(w http.ResponseWriter, r *http.Request) {
	d, ok := s.grantedDrop(w, r)
	if !ok {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "권한이 없습니다", http.StatusUnauthorized)
		}
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition("drop-"+d.ID+".zip"))
	w.Header().Set("Cache-Control", "private, no-store")
	s.store.RecordDownload(d.ID, s.now())
	zw := zip.NewWriter(w)
	for i, fm := range d.Files {
		f, err := s.store.OpenFile(d, i)
		if err != nil {
			slog.Error("zip open", "id", d.ID, "n", i, "err", err)
			return
		}
		// 대부분 이미 압축된 파일이라 저장(Store)만 한다 — CPU 를 아끼고 바로 흘려보낸다.
		hw, err := zw.CreateHeader(&zip.FileHeader{Name: fm.Name, Method: zip.Store, Modified: d.CreatedAt})
		if err == nil {
			_, err = io.Copy(hw, f)
		}
		f.Close()
		if err != nil {
			slog.Warn("zip write", "id", d.ID, "err", err)
			return
		}
	}
	zw.Close()
}

// ---- 응답 도우미 ----

type DropView struct {
	ID        string     `json:"id"`
	Password  string     `json:"password,omitempty"`
	URL       string     `json:"url"`
	Files     []FileMeta `json:"files"`
	Bytes     int64      `json:"bytes"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	Via       string     `json:"via"`
	Pending   bool       `json:"pending"`
	Downloads int        `json:"downloads"`
}

func dropView(d *Drop, base string) DropView {
	return DropView{
		ID: d.ID, URL: base + "/get?id=" + url.QueryEscape(d.ID), Files: d.Files, Bytes: d.TotalSize(),
		CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt, CreatedBy: d.CreatedBy, Via: d.Via,
		Pending: d.Pending, Downloads: d.Downloads,
	}
}

// baseURL 은 사용자에게 보여줄 주소다. 클러스터 안에서 내부 이름으로 들어온 요청에도 공개 주소를
// 돌려주도록 PUBLIC_BASE_URL 이 있으면 그것을 쓴다.
func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.PublicBaseURL != "" {
		return s.cfg.PublicBaseURL
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) storeErr(w http.ResponseWriter, err error) {
	var ie *InvalidError
	switch {
	case errors.As(err, &ie):
		writeErr(w, http.StatusBadRequest, ie.Msg)
	case errors.Is(err, ErrIDTaken):
		writeErr(w, http.StatusConflict, "이미 쓰고 있는 아이디입니다")
	case errors.Is(err, ErrQuota):
		writeErr(w, http.StatusInsufficientStorage, "저장 공간이 부족합니다 ("+err.Error()+")")
	case errors.Is(err, ErrIncomplete):
		writeErr(w, http.StatusConflict, "아직 다 올라가지 않았습니다: "+err.Error())
	case errors.Is(err, ErrUploadKey), errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "찾을 수 없습니다")
	default:
		slog.Error("store", "err", err)
		writeErr(w, http.StatusInternalServerError, "서버 오류")
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) page(w http.ResponseWriter, code int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template", "name", name, "err", err)
	}
}

func contentDisposition(name string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	return mime.FormatMediaType("attachment", map[string]string{"filename": ascii}) +
		"; filename*=UTF-8''" + url.PathEscape(name)
}
