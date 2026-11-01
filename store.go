package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// 저장 구조(전부 DATA_DIR 아래, 데이터베이스 없음):
//
//	secret                  쿠키 서명 키(첫 기동 때 생성)
//	drops/<id>/meta.json    보관함 메타데이터(비밀번호는 해시만)
//	drops/<id>/files/<n>    n 번째 파일 내용
//	tokens/<sha256>.json    업로드 링크·API 키(원문은 저장하지 않는다)
//
// 쓰기 프로세스는 하나(replicas 0/1, strategy Recreate)라는 전제다. 정리 CronJob 은 만료된
// 보관함 디렉터리를 통째로 지우기만 하므로 웹 프로세스와 겹쳐도 안전하다.

var (
	ErrNotFound     = errors.New("not found")
	ErrIDTaken      = errors.New("id already in use")
	ErrInvalid      = errors.New("invalid request")
	ErrQuota        = errors.New("storage quota exceeded")
	ErrOffset       = errors.New("offset mismatch")
	ErrIncomplete   = errors.New("upload incomplete")
	ErrUploadKey    = errors.New("invalid upload key")
	ErrTokenExpired = errors.New("token expired or used up")
)

// InvalidError 는 사용자에게 그대로 보여줄 수 있는 검증 오류다.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }
func (e *InvalidError) Unwrap() error { return ErrInvalid }

func invalid(format string, a ...any) error { return &InvalidError{fmt.Sprintf(format, a...)} }

// pendingTTL 은 완료되지 않은 업로드를 정리하기까지의 시간이다.
const pendingTTL = 24 * time.Hour

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,39}$`)

// reservedIDs 는 공유 주소(/{id})와 겹치는 고정 경로라 아이디로 쓸 수 없다.
// 경로를 새로 만들면 여기에도 넣는다(flux-cd-apps 의 공개 라우트 정규식과 함께).
var reservedIDs = map[string]bool{"admin": true, "api": true, "get": true, "static": true, "healthz": true}

func reservedID(id string) bool { return reservedIDs[id] }

type FileMeta struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type Drop struct {
	ID            string     `json:"id"`
	PasswordHash  string     `json:"password_hash"`
	Files         []FileMeta `json:"files"`
	Days          int        `json:"days"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedBy     string     `json:"created_by"`
	Via           string     `json:"via"` // admin | link | apikey
	TokenID       string     `json:"token_id,omitempty"`
	Pending       bool       `json:"pending"`
	UploadKeyHash string     `json:"upload_key_hash,omitempty"`
	Downloads     int        `json:"downloads"`
	LastDownload  *time.Time `json:"last_download,omitempty"`
}

func (d *Drop) TotalSize() int64 {
	var n int64
	for _, f := range d.Files {
		n += f.Size
	}
	return n
}

func (d *Drop) Expired(now time.Time) bool {
	if d.Pending {
		return now.Sub(d.CreatedAt) > pendingTTL
	}
	return !now.Before(d.ExpiresAt)
}

type Token struct {
	ID        string     `json:"id"`   // 공개 식별자(해시 앞 12자)
	Hash      string     `json:"hash"` // sha256(원문)
	Kind      string     `json:"kind"` // link | apikey
	Label     string     `json:"label"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	MaxUses   int        `json:"max_uses,omitempty"` // 0 = 무제한(link 는 항상 > 0)
	Uses      int        `json:"uses"`
	MaxDays   int        `json:"max_days"`
	Revoked   bool       `json:"revoked"`
}

func (t *Token) Usable(now time.Time) bool {
	if t.Revoked {
		return false
	}
	if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
		return false
	}
	if t.MaxUses > 0 && t.Uses >= t.MaxUses {
		return false
	}
	return true
}

type Store struct {
	dir   string
	mu    sync.Mutex // 메타데이터 읽기-수정-쓰기 직렬화
	locks sync.Map   // id → *sync.Mutex, 파일 조각 쓰기 직렬화
}

func OpenStore(dir string) (*Store, error) {
	for _, d := range []string{dir, filepath.Join(dir, "drops"), filepath.Join(dir, "tokens")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

// Secret 은 쿠키 서명 키를 돌려준다. 없으면 만들어 저장한다.
func (s *Store) Secret() ([]byte, error) {
	p := filepath.Join(s.dir, "secret")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := []byte(randomString(64, alnum))
	if err := writeFileAtomic(p, b); err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (s *Store) dropDir(id string) string { return filepath.Join(s.dir, "drops", id) }
func (s *Store) metaPath(id string) string {
	return filepath.Join(s.dropDir(id), "meta.json")
}
func (s *Store) filePath(id string, n int) string {
	return filepath.Join(s.dropDir(id), "files", fmt.Sprint(n))
}

func (s *Store) readDrop(id string) (*Drop, error) {
	if !idRe.MatchString(id) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(s.metaPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var d Drop
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) writeDrop(d *Drop) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.metaPath(d.ID), b)
}

// Get 은 받을 수 있는(완료됐고 만료되지 않은) 보관함만 돌려준다.
func (s *Store) Get(id string, now time.Time) (*Drop, error) {
	d, err := s.readDrop(id)
	if err != nil {
		return nil, err
	}
	if d.Pending || d.Expired(now) {
		return nil, ErrNotFound
	}
	return d, nil
}

// List 는 모든 보관함(업로드 중 포함, 만료 제외)을 만료 임박 순으로 돌려준다.
func (s *Store) List(now time.Time) ([]*Drop, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "drops"))
	if err != nil {
		return nil, err
	}
	var out []*Drop
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d, err := s.readDrop(e.Name())
		if err != nil || d.Expired(now) {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out, nil
}

// UsedBytes 는 저장소 사용량(업로드 중인 것은 선언 크기)이다. 만료됐지만 아직 지워지지 않은
// 보관함도 디스크를 차지하므로 센다.
func (s *Store) usedBytes() (int64, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "drops"))
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range entries {
		if d, err := s.readDrop(e.Name()); err == nil {
			n += d.TotalSize()
		}
	}
	return n, nil
}

type CreateRequest struct {
	Files    []FileMeta `json:"files"`
	ID       string     `json:"id"`
	Password string     `json:"password"`
	Days     int        `json:"days"`
}

type Creator struct {
	Name    string
	Via     string
	TokenID string
	MaxDays int
}

type Limits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
	MaxDays       int
	DefaultDays   int
}

// CreatePending 은 업로드를 시작한다. 돌려주는 password·uploadKey 원문은 이때만 알 수 있다.
func (s *Store) CreatePending(req CreateRequest, by Creator, lim Limits, now time.Time) (d *Drop, password, uploadKey string, err error) {
	if len(req.Files) == 0 {
		return nil, "", "", invalid("파일을 하나 이상 선택하세요")
	}
	if len(req.Files) > lim.MaxFiles {
		return nil, "", "", invalid("파일은 한 번에 %d개까지 올릴 수 있습니다", lim.MaxFiles)
	}
	files := make([]FileMeta, len(req.Files))
	var total int64
	seen := map[string]int{}
	for i, f := range req.Files {
		if f.Size < 0 || f.Size > lim.MaxFileBytes {
			return nil, "", "", invalid("%q: 파일 하나는 %s까지입니다", f.Name, humanBytes(lim.MaxFileBytes))
		}
		name := uniqueName(cleanFileName(f.Name), seen)
		files[i] = FileMeta{Name: name, Size: f.Size}
		total += f.Size
	}

	maxDays := lim.MaxDays
	if by.MaxDays > 0 && by.MaxDays < maxDays {
		maxDays = by.MaxDays
	}
	days := req.Days
	if days == 0 {
		days = min(lim.DefaultDays, maxDays)
	}
	if days < 1 || days > maxDays {
		return nil, "", "", invalid("보관 기간은 1~%d일입니다", maxDays)
	}

	id := strings.ToLower(strings.TrimSpace(req.ID))
	if id != "" && !idRe.MatchString(id) {
		return nil, "", "", invalid("아이디는 영문 소문자·숫자·하이픈 3~40자입니다")
	}
	if reservedID(id) {
		return nil, "", "", invalid("%q 는 쓸 수 없는 아이디입니다", id)
	}
	password = strings.TrimSpace(req.Password)
	if password == "" {
		password = randomString(8, friendly)
	} else if utf8.RuneCountInString(password) < 6 || len(password) > 128 {
		return nil, "", "", invalid("비밀번호는 6자 이상입니다")
	}
	pwHash, err := hashPassword(password)
	if err != nil {
		return nil, "", "", err
	}
	uploadKey = randomString(32, alnum)

	s.mu.Lock()
	defer s.mu.Unlock()

	used, err := s.usedBytes()
	if err != nil {
		return nil, "", "", err
	}
	if used+total > lim.MaxTotalBytes {
		return nil, "", "", fmt.Errorf("%w: %s 남음", ErrQuota, humanBytes(max(0, lim.MaxTotalBytes-used)))
	}

	if id == "" {
		for range 20 {
			cand := randomString(6, friendly)
			if err := s.claimID(cand, now); err == nil {
				id = cand
				break
			}
		}
		if id == "" {
			return nil, "", "", errors.New("could not allocate id")
		}
	} else if err := s.claimID(id, now); err != nil {
		return nil, "", "", err
	}

	d = &Drop{
		ID:            id,
		PasswordHash:  pwHash,
		Files:         files,
		Days:          days,
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Duration(days) * 24 * time.Hour),
		CreatedBy:     by.Name,
		Via:           by.Via,
		TokenID:       by.TokenID,
		Pending:       true,
		UploadKeyHash: sha256Hex(uploadKey),
	}
	if err := os.MkdirAll(filepath.Join(s.dropDir(id), "files"), 0o750); err != nil {
		return nil, "", "", err
	}
	for i := range files {
		f, err := os.OpenFile(s.filePath(id, i), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return nil, "", "", err
		}
		f.Close()
	}
	if err := s.writeDrop(d); err != nil {
		os.RemoveAll(s.dropDir(id))
		return nil, "", "", err
	}
	return d, password, uploadKey, nil
}

// claimID 는 디렉터리를 만들어 아이디를 차지한다. 만료된 보관함이 남아 있으면 지우고 재사용한다.
// s.mu 를 잡은 채 부른다.
func (s *Store) claimID(id string, now time.Time) error {
	dir := s.dropDir(id)
	err := os.Mkdir(dir, 0o750)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return err
	}
	old, rerr := s.readDrop(id)
	if rerr == nil && !old.Expired(now) {
		return ErrIDTaken
	}
	if rerr != nil && !errors.Is(rerr, ErrNotFound) {
		// 메타가 깨진 디렉터리: 손대지 않는다.
		return ErrIDTaken
	}
	if rerr != nil {
		// 메타 없는 디렉터리 — 다른 요청이 막 만든 참일 수 있으니 오래된 것만 치운다.
		if st, serr := os.Stat(dir); serr != nil || now.Sub(st.ModTime()) < time.Hour {
			return ErrIDTaken
		}
	}
	if err := s.removeDropDir(id); err != nil {
		return err
	}
	return os.Mkdir(dir, 0o750)
}

func (s *Store) lockFor(id string) *sync.Mutex {
	m, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// pendingFor 는 업로드 키를 확인하고 진행 중인 보관함을 돌려준다.
func (s *Store) pendingFor(id, key string, now time.Time) (*Drop, error) {
	d, err := s.readDrop(id)
	if err != nil {
		return nil, err
	}
	if !d.Pending || d.Expired(now) {
		return nil, ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(d.UploadKeyHash), []byte(sha256Hex(key))) != 1 {
		return nil, ErrUploadKey
	}
	return d, nil
}

// Received 는 n 번째 파일이 지금까지 받은 바이트 수다.
func (s *Store) Received(id string, n int) (int64, error) {
	st, err := os.Stat(s.filePath(id, n))
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// WriteChunk 는 n 번째 파일의 offset 위치에 조각을 붙인다. offset 이 지금까지 받은 크기와
// 다르면 ErrOffset 과 함께 실제 받은 크기를 돌려준다 — 클라이언트는 거기서 이어 올린다.
func (s *Store) WriteChunk(id, key string, n int, offset int64, r io.Reader, maxChunk int64, now time.Time) (int64, error) {
	d, err := s.pendingFor(id, key, now)
	if err != nil {
		return 0, err
	}
	if n < 0 || n >= len(d.Files) {
		return 0, ErrNotFound
	}
	lk := s.lockFor(id)
	lk.Lock()
	defer lk.Unlock()

	got, err := s.Received(id, n)
	if err != nil {
		return 0, err
	}
	if offset != got {
		return got, ErrOffset
	}
	remain := d.Files[n].Size - got
	limit := min(remain, maxChunk)

	f, err := os.OpenFile(s.filePath(id, n), os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return got, err
	}
	written, cerr := io.Copy(f, io.LimitReader(r, limit))
	serr := f.Sync()
	f.Close()
	got += written
	if cerr != nil {
		return got, cerr
	}
	if serr != nil {
		return got, serr
	}
	// 남은 크기를 넘는 본문은 거부한다(선언 크기가 진실).
	var probe [1]byte
	if written == limit && limit == remain {
		if k, _ := r.Read(probe[:]); k > 0 {
			return got, invalid("파일이 선언한 크기보다 큽니다")
		}
	}
	return got, nil
}

// Complete 는 모든 파일이 다 왔는지 확인하고 보관함을 연다. 보관 기간은 지금부터 센다.
func (s *Store) Complete(id, key string, now time.Time) (*Drop, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.pendingFor(id, key, now)
	if err != nil {
		return nil, err
	}
	for i, f := range d.Files {
		got, err := s.Received(id, i)
		if err != nil {
			return nil, err
		}
		if got != f.Size {
			return nil, fmt.Errorf("%w: %s (%d/%d)", ErrIncomplete, f.Name, got, f.Size)
		}
	}
	d.Pending = false
	d.UploadKeyHash = ""
	d.ExpiresAt = now.Add(time.Duration(d.Days) * 24 * time.Hour)
	if err := s.writeDrop(d); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) RecordDownload(id string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.readDrop(id)
	if err != nil {
		return
	}
	d.Downloads++
	d.LastDownload = &now
	_ = s.writeDrop(d)
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.readDrop(id); err != nil {
		return err
	}
	return s.removeDropDir(id)
}

// removeDropDir 은 먼저 이름을 바꿔(원자적) 더 이상 보이지 않게 한 뒤 지운다.
func (s *Store) removeDropDir(id string) error {
	trash := filepath.Join(s.dir, "drops", ".trash-"+id+"-"+randomString(6, alnum))
	if err := os.Rename(s.dropDir(id), trash); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.RemoveAll(trash)
}

func (s *Store) OpenFile(d *Drop, n int) (*os.File, error) {
	if n < 0 || n >= len(d.Files) {
		return nil, ErrNotFound
	}
	return os.Open(s.filePath(d.ID, n))
}

type CleanupResult struct {
	Drops, Tokens int
}

// Cleanup 은 만료된 보관함·24시간 넘게 끝나지 않은 업로드·쓸 수 없게 된 지 7일 지난 토큰을 지운다.
func (s *Store) Cleanup(now time.Time) (CleanupResult, error) {
	var res CleanupResult
	entries, err := os.ReadDir(filepath.Join(s.dir, "drops"))
	if err != nil {
		return res, err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".trash-") {
			_ = os.RemoveAll(filepath.Join(s.dir, "drops", name))
			continue
		}
		s.mu.Lock()
		d, err := s.readDrop(name)
		if err == nil && d.Expired(now) {
			if s.removeDropDir(name) == nil {
				res.Drops++
			}
		}
		s.mu.Unlock()
	}

	toks, err := s.ListTokens()
	if err != nil {
		return res, err
	}
	for _, t := range toks {
		dead := t.Revoked || (t.MaxUses > 0 && t.Uses >= t.MaxUses)
		deadSince := t.CreatedAt
		if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
			dead, deadSince = true, *t.ExpiresAt
		}
		if dead && now.Sub(deadSince) > 7*24*time.Hour {
			if os.Remove(s.tokenPath(t.Hash)) == nil {
				res.Tokens++
			}
		}
	}
	return res, nil
}

// ---- 토큰 ----

func (s *Store) tokenPath(hash string) string {
	return filepath.Join(s.dir, "tokens", hash+".json")
}

type TokenRequest struct {
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	ValidHours int    `json:"valid_hours"` // link: 필수, apikey: 0 = 만료 없음
	MaxUses    int    `json:"max_uses"`    // link 전용
	MaxDays    int    `json:"max_days"`
	// validFor 는 서비스 계정 교환이 쓰는 분 단위 만료다(관리 API 로는 받지 않는다). 있으면 ValidHours 대신 쓴다.
	validFor time.Duration
}

// CreateToken 은 원문을 한 번만 돌려준다.
func (s *Store) CreateToken(req TokenRequest, createdBy string, globalMaxDays int, now time.Time) (*Token, string, error) {
	t := &Token{Kind: req.Kind, CreatedBy: createdBy, CreatedAt: now}
	t.Label = strings.TrimSpace(req.Label)
	if utf8.RuneCountInString(t.Label) > 80 {
		return nil, "", invalid("이름은 80자까지입니다")
	}
	if req.MaxDays == 0 {
		req.MaxDays = globalMaxDays
	}
	if req.MaxDays < 1 || req.MaxDays > globalMaxDays {
		return nil, "", invalid("최대 보관 기간은 1~%d일입니다", globalMaxDays)
	}
	t.MaxDays = req.MaxDays
	var prefix string
	switch req.Kind {
	case "link":
		prefix = ""
		if req.ValidHours < 1 || req.ValidHours > 24*30 {
			return nil, "", invalid("링크 유효 시간은 1~720시간입니다")
		}
		if req.MaxUses < 1 || req.MaxUses > 1000 {
			return nil, "", invalid("사용 횟수는 1~1000회입니다")
		}
		t.MaxUses = req.MaxUses
	case "apikey":
		prefix = "drk_"
		if req.ValidHours < 0 || req.ValidHours > 24*366 {
			return nil, "", invalid("API 키 유효 시간은 0(무기한)~8784시간입니다")
		}
	default:
		return nil, "", invalid("kind 는 link 또는 apikey 입니다")
	}
	switch {
	case req.validFor > 0:
		exp := now.Add(req.validFor)
		t.ExpiresAt = &exp
	case req.ValidHours > 0:
		exp := now.Add(time.Duration(req.ValidHours) * time.Hour)
		t.ExpiresAt = &exp
	}
	secret := prefix + randomString(32, alnum)
	t.Hash = sha256Hex(secret)
	t.ID = t.Hash[:12]
	if err := s.writeToken(t); err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

func (s *Store) writeToken(t *Token) error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.tokenPath(t.Hash), b)
}

// LookupToken 은 원문으로 쓸 수 있는 토큰을 찾는다.
func (s *Store) LookupToken(secret, kind string, now time.Time) (*Token, error) {
	if secret == "" || len(secret) > 200 {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(s.tokenPath(sha256Hex(secret)))
	if err != nil {
		return nil, ErrNotFound
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil || t.Kind != kind {
		return nil, ErrNotFound
	}
	if !t.Usable(now) {
		return &t, ErrTokenExpired
	}
	return &t, nil
}

// UseToken 은 사용 횟수를 올린다. 한도를 넘었으면 ErrTokenExpired.
func (s *Store) UseToken(hash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.tokenPath(hash))
	if err != nil {
		return ErrNotFound
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	if !t.Usable(now) {
		return ErrTokenExpired
	}
	t.Uses++
	return s.writeToken(&t)
}

func (s *Store) ListTokens() ([]*Token, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "tokens"))
	if err != nil {
		return nil, err
	}
	var out []*Token
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, "tokens", e.Name()))
		if err != nil {
			continue
		}
		var t Token
		if json.Unmarshal(b, &t) == nil {
			out = append(out, &t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) RevokeToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	toks, err := s.ListTokens()
	if err != nil {
		return err
	}
	for _, t := range toks {
		if t.ID == id {
			t.Revoked = true
			return s.writeToken(t)
		}
	}
	return ErrNotFound
}

// ---- 도우미 ----

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp-" + randomString(6, alnum)
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// cleanFileName 은 경로·제어 문자를 걷어낸 표시용 이름을 만든다(디스크 경로에는 쓰지 않는다).
func cleanFileName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '"' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(name, ""))
	name = strings.TrimSpace(name)
	for len(name) > 200 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	if name == "" || name == "." || name == ".." {
		name = "file"
	}
	return name
}

// uniqueName 은 같은 보관함 안의 이름 충돌을 "이름 (2).확장자" 식으로 푼다.
func uniqueName(name string, seen map[string]int) string {
	key := strings.ToLower(name)
	if seen[key] == 0 {
		seen[key] = 1
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := seen[key] + 1; ; i++ {
		cand := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if seen[strings.ToLower(cand)] == 0 {
			seen[key] = i
			seen[strings.ToLower(cand)] = 1
			return cand
		}
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= GiB:
		return fmt.Sprintf("%.1fGB", float64(n)/float64(GiB))
	case n >= MiB:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(MiB))
	case n >= KiB:
		return fmt.Sprintf("%.1fKB", float64(n)/float64(KiB))
	}
	return fmt.Sprintf("%dB", n)
}
