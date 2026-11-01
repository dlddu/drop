package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testEnv struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	now time.Time
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := Config{
		Addr: ":0", DataDir: t.TempDir(), MaxFileBytes: 1 * MiB, MaxTotalBytes: 3 * MiB, MaxFiles: 10,
		MaxDays: 30, DefaultDays: 7, ChunkBytes: 64 * KiB, MaxChunkBytes: 256 * KiB,
	}
	st, err := OpenStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, srv: s, now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	s.now = func() time.Time { return e.now }
	e.ts = httptest.NewServer(s)
	t.Cleanup(e.ts.Close)
	return e
}

func (e *testEnv) do(method, path string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, b
}

var admin = map[string]string{"Remote-User": "alice", "X-Drop": "1", "Content-Type": "application/json"}

func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("json: %v: %s", err, b)
	}
}

// upload 은 조각 API 로 파일들을 올리고 (id, password) 를 돌려준다.
func (e *testEnv) upload(prefix string, hdr map[string]string, req map[string]any, contents [][]byte, chunk int) (string, string) {
	e.t.Helper()
	b, _ := json.Marshal(req)
	res, body := e.do("POST", prefix+"/uploads", bytes.NewReader(b), hdr)
	if res.StatusCode != 201 {
		e.t.Fatalf("init: %d %s", res.StatusCode, body)
	}
	var ir initResponse
	mustJSON(e.t, body, &ir)
	base := prefix + "/uploads/" + ir.ID + "/" + ir.UploadKey
	for n, c := range contents {
		for off := 0; off < len(c); off += chunk {
			end := min(off+chunk, len(c))
			res, body := e.do("PUT", base+"/files/"+itoa(n)+"?offset="+itoa(off), bytes.NewReader(c[off:end]), hdr)
			if res.StatusCode != 200 {
				e.t.Fatalf("chunk: %d %s", res.StatusCode, body)
			}
		}
	}
	res, body = e.do("POST", base+"/complete", nil, hdr)
	if res.StatusCode != 200 {
		e.t.Fatalf("complete: %d %s", res.StatusCode, body)
	}
	return ir.ID, ir.Password
}

func itoa(n int) string    { return jsonInt(n) }
func jsonInt(n int) string { b, _ := json.Marshal(n); return string(b) }

func files(req ...[2]any) []map[string]any {
	var out []map[string]any
	for _, r := range req {
		out = append(out, map[string]any{"name": r[0], "size": r[1]})
	}
	return out
}

func TestAdminUploadAndReceive(t *testing.T) {
	e := newEnv(t)
	a := bytes.Repeat([]byte("a"), 200*1024+7)
	b := []byte("hello")
	id, pw := e.upload("/admin/api", admin, map[string]any{
		"files": files([2]any{"report.pdf", len(a)}, [2]any{"../../etc/note.txt", len(b)}), "id": "Trip-Photos", "days": 3,
	}, [][]byte{a, b}, 64*1024)
	if id != "trip-photos" {
		t.Fatalf("id = %q", id)
	}
	if len(pw) != 8 {
		t.Fatalf("generated password %q", pw)
	}

	// 브라우저 흐름: 폼 → 쿠키 → 목록 → 파일
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	res, err := c.PostForm(e.ts.URL+"/get", url.Values{"id": {"trip-photos"}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(page), "report.pdf") || !strings.Contains(string(page), "note.txt") {
		t.Fatalf("files page: %d %s", res.StatusCode, page)
	}
	if strings.Contains(string(page), "../") {
		t.Fatal("path traversal name leaked")
	}
	res, err = c.Get(e.ts.URL + "/get/trip-photos/f/0")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !bytes.Equal(got, a) {
		t.Fatalf("download mismatch: %d bytes", len(got))
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "report.pdf") {
		t.Fatalf("content-disposition %q", cd)
	}

	// curl -u 흐름 + Range
	res2, body := e.do("GET", "/get/trip-photos/f/1", nil, map[string]string{"Authorization": basic("trip-photos", pw), "Range": "bytes=1-3"})
	if res2.StatusCode != 206 || string(body) != "ell" {
		t.Fatalf("range: %d %q", res2.StatusCode, body)
	}

	// zip
	res, err = c.Get(e.ts.URL + "/get/trip-photos/all.zip")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !bytes.HasPrefix(zb, []byte("PK")) {
		t.Fatalf("zip: %d", res.StatusCode)
	}

	// 쿠키 없이는 못 받는다
	res3, _ := e.do("GET", "/get/trip-photos/f/0", nil, nil)
	if res3.StatusCode != 401 {
		t.Fatalf("no cookie: %d", res3.StatusCode)
	}
}

func basic(u, p string) string {
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth(u, p)
	return req.Header.Get("Authorization")
}

func TestWrongPasswordLockout(t *testing.T) {
	e := newEnv(t)
	id, pw := e.upload("/admin/api", admin, map[string]any{"files": files([2]any{"x", 1}), "id": "abc", "password": "secret1"}, [][]byte{{'x'}}, 10)
	if pw != "secret1" {
		t.Fatal(pw)
	}
	form := func(p string) int {
		res, _ := e.do("POST", "/get", strings.NewReader(url.Values{"id": {id}, "password": {p}}.Encode()),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded", "X-Real-Ip": "1.2.3.4"})
		return res.StatusCode
	}
	for i := 0; i < 5; i++ {
		if c := form("nope-nope"); c != 401 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	if c := form("secret1"); c != 429 {
		t.Fatalf("locked: want 429 got %d", c)
	}
	e.now = e.now.Add(16 * time.Minute)
	if c := form("secret1"); c != 303 {
		t.Fatalf("after window: %d", c)
	}
}

func TestExpiryAndCleanup(t *testing.T) {
	e := newEnv(t)
	id, pw := e.upload("/admin/api", admin, map[string]any{"files": files([2]any{"x", 1}), "days": 1}, [][]byte{{'x'}}, 10)
	e.now = e.now.Add(25 * time.Hour)
	res, _ := e.do("GET", "/get/"+id+"/f/0", nil, map[string]string{"Authorization": basic(id, pw)})
	if res.StatusCode != 401 {
		t.Fatalf("expired drop still served: %d", res.StatusCode)
	}
	r, err := e.srv.store.Cleanup(e.now)
	if err != nil || r.Drops != 1 {
		t.Fatalf("cleanup: %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(e.srv.cfg.DataDir, "drops", id)); !os.IsNotExist(err) {
		t.Fatal("drop dir still on disk")
	}
}

func TestDaysLimit(t *testing.T) {
	e := newEnv(t)
	b, _ := json.Marshal(map[string]any{"files": files([2]any{"x", 1}), "days": 31})
	res, body := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin)
	if res.StatusCode != 400 {
		t.Fatalf("31 days: %d %s", res.StatusCode, body)
	}
}

func TestAdminRequiresAuthelia(t *testing.T) {
	e := newEnv(t)
	res, _ := e.do("GET", "/admin/api/drops", nil, nil)
	if res.StatusCode != 401 {
		t.Fatalf("no remote-user: %d", res.StatusCode)
	}
	// CSRF: 사용자 지정 헤더 없는 쓰기 거부
	res, _ = e.do("POST", "/admin/api/tokens", strings.NewReader(`{"kind":"link","valid_hours":1,"max_uses":1}`),
		map[string]string{"Remote-User": "alice", "Content-Type": "application/json"})
	if res.StatusCode != 403 {
		t.Fatalf("csrf: %d", res.StatusCode)
	}
	res, _ = e.do("GET", "/admin", nil, nil)
	if res.StatusCode != 401 {
		t.Fatalf("admin page: %d", res.StatusCode)
	}
}

func TestUploadLink(t *testing.T) {
	e := newEnv(t)
	res, body := e.do("POST", "/admin/api/tokens", strings.NewReader(`{"kind":"link","label":"kim","valid_hours":24,"max_uses":1,"max_days":3}`), admin)
	if res.StatusCode != 201 {
		t.Fatalf("create link: %d %s", res.StatusCode, body)
	}
	var tok struct{ Secret, URL string }
	mustJSON(t, body, &tok)
	if !strings.HasSuffix(tok.URL, "/u/"+tok.Secret) {
		t.Fatalf("url %q", tok.URL)
	}
	if res, _ := e.do("GET", "/u/"+tok.Secret, nil, nil); res.StatusCode != 200 {
		t.Fatalf("link page: %d", res.StatusCode)
	}
	hdr := map[string]string{"X-Drop": "1", "Content-Type": "application/json"}
	prefix := "/u/" + tok.Secret + "/api"

	// 링크의 최대 보관 기간(3일)을 넘을 수 없다
	b, _ := json.Marshal(map[string]any{"files": files([2]any{"x", 1}), "days": 4})
	if res, _ := e.do("POST", prefix+"/uploads", bytes.NewReader(b), hdr); res.StatusCode != 400 {
		t.Fatalf("days over link max: %d", res.StatusCode)
	}

	id, pw := e.upload(prefix, hdr, map[string]any{"files": files([2]any{"doc.txt", 3})}, [][]byte{[]byte("abc")}, 2)
	d, err := e.srv.store.Get(id, e.now)
	if err != nil || d.CreatedBy != "link:kim" || d.Days != 3 {
		t.Fatalf("drop %+v %v", d, err)
	}
	_ = pw
	// 1회용: 두 번째는 막힌다
	if res, _ := e.do("GET", "/u/"+tok.Secret, nil, nil); res.StatusCode != 410 {
		t.Fatalf("used link: %d", res.StatusCode)
	}
	if res, _ := e.do("GET", "/u/not-a-token", nil, nil); res.StatusCode != 404 {
		t.Fatalf("bogus link: %d", res.StatusCode)
	}
}

func TestAPIKeySimpleUploadAndRevoke(t *testing.T) {
	e := newEnv(t)
	res, body := e.do("POST", "/admin/api/tokens", strings.NewReader(`{"kind":"apikey","label":"backup"}`), admin)
	if res.StatusCode != 201 {
		t.Fatalf("create key: %d %s", res.StatusCode, body)
	}
	var tok struct{ ID, Secret string }
	mustJSON(t, body, &tok)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("id", "nightly")
	mw.WriteField("days", "2")
	fw, _ := mw.CreateFormFile("file", "dump.sql")
	fw.Write([]byte("select 1;"))
	mw.Close()
	auth := map[string]string{"Authorization": "Bearer " + tok.Secret, "Content-Type": mw.FormDataContentType()}
	res, body = e.do("POST", "/api/v1/drops", &buf, auth)
	if res.StatusCode != 201 {
		t.Fatalf("simple upload: %d %s", res.StatusCode, body)
	}
	var v DropView
	mustJSON(t, body, &v)
	if v.ID != "nightly" || v.Password == "" || v.Bytes != 9 {
		t.Fatalf("view %+v", v)
	}
	res, body = e.do("GET", "/get/nightly/f/0", nil, map[string]string{"Authorization": basic("nightly", v.Password)})
	if res.StatusCode != 200 || string(body) != "select 1;" {
		t.Fatalf("download: %d %q", res.StatusCode, body)
	}
	// 조각 API 도 같은 키로(X-Drop 불필요)
	e.upload("/api/v1", map[string]string{"Authorization": "Bearer " + tok.Secret, "Content-Type": "application/json"},
		map[string]any{"files": files([2]any{"big.bin", 5})}, [][]byte{[]byte("12345")}, 2)

	if res, _ := e.do("DELETE", "/admin/api/tokens/"+tok.ID, nil, admin); res.StatusCode != 204 {
		t.Fatalf("revoke: %d", res.StatusCode)
	}
	if res, _ := e.do("GET", "/api/v1/drops", nil, map[string]string{"Authorization": "Bearer " + tok.Secret}); res.StatusCode != 401 {
		t.Fatalf("revoked key works: %d", res.StatusCode)
	}
}

func TestChunkResumeAndLimits(t *testing.T) {
	e := newEnv(t)
	b, _ := json.Marshal(map[string]any{"files": files([2]any{"a", 10})})
	res, body := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin)
	var ir initResponse
	mustJSON(t, body, &ir)
	base := "/admin/api/uploads/" + ir.ID + "/" + ir.UploadKey
	e.do("PUT", base+"/files/0?offset=0", strings.NewReader("12345"), admin)
	// 같은 조각을 다시 보내면 409 와 실제 받은 위치
	res, body = e.do("PUT", base+"/files/0?offset=0", strings.NewReader("12345"), admin)
	if res.StatusCode != 409 || !strings.Contains(string(body), `"received":5`) {
		t.Fatalf("resume: %d %s", res.StatusCode, body)
	}
	// 미완료 상태로 완료 불가
	if res, _ := e.do("POST", base+"/complete", nil, admin); res.StatusCode != 409 {
		t.Fatalf("incomplete complete: %d", res.StatusCode)
	}
	// 선언보다 큰 본문 거부
	if res, _ := e.do("PUT", base+"/files/0?offset=5", strings.NewReader("678901"), admin); res.StatusCode != 400 {
		t.Fatalf("oversize: %d", res.StatusCode)
	}
	// 잘못된 업로드 키
	if res, _ := e.do("PUT", "/admin/api/uploads/"+ir.ID+"/wrong/files/0?offset=0", strings.NewReader("x"), admin); res.StatusCode != 404 {
		t.Fatalf("bad key: %d", res.StatusCode)
	}
	// 파일 크기·전체 한도
	b, _ = json.Marshal(map[string]any{"files": files([2]any{"big", 2 * MiB})})
	if res, _ := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin); res.StatusCode != 400 {
		t.Fatalf("file too big: %d", res.StatusCode)
	}
	b, _ = json.Marshal(map[string]any{"files": files([2]any{"a", MiB}, [2]any{"b", MiB}, [2]any{"c", MiB})})
	if res, _ := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin); res.StatusCode != 507 {
		t.Fatalf("quota: %d", res.StatusCode)
	}
	// 중복 아이디
	b, _ = json.Marshal(map[string]any{"files": files([2]any{"a", 1}), "id": ir.ID})
	if res, _ := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin); res.StatusCode != 409 {
		t.Fatalf("dup id: %d", res.StatusCode)
	}
	// 업로드 중인 보관함은 받기에서 보이지 않는다
	res, _ = e.do("GET", "/get/"+ir.ID+"/f/0", nil, map[string]string{"Authorization": basic(ir.ID, ir.Password)})
	if res.StatusCode != 401 {
		t.Fatalf("pending visible: %d", res.StatusCode)
	}
	// 24시간 지난 미완료 업로드는 정리된다
	e.now = e.now.Add(25 * time.Hour)
	if r, _ := e.srv.store.Cleanup(e.now); r.Drops != 1 {
		t.Fatalf("pending cleanup %+v", r)
	}
}

func TestRootAndHealth(t *testing.T) {
	e := newEnv(t)
	if res, _ := e.do("GET", "/", nil, nil); res.StatusCode != 302 || res.Header.Get("Location") != "/get" {
		t.Fatalf("root: %d", res.StatusCode)
	}
	if res, body := e.do("GET", "/healthz", nil, nil); res.StatusCode != 200 || string(body) != "ok" {
		t.Fatal("healthz")
	}
	if res, _ := e.do("GET", "/static/style.css", nil, nil); res.StatusCode != 200 {
		t.Fatal("static")
	}
}
