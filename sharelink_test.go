package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func TestShortShareURL(t *testing.T) {
	e := newEnv(t)
	id, pw := e.upload("/admin/api", admin, map[string]any{
		"files": files([2]any{"photo.jpg", 3}), "id": "trip-photos", "password": "secret-pw",
	}, [][]byte{[]byte("jpg")}, 3)

	// /{id}: 아이디가 채워진 폼, 비밀번호 칸은 비어 있다
	res, body := e.do("GET", "/"+id, nil, nil)
	if res.StatusCode != 200 || !strings.Contains(string(body), `value="trip-photos"`) || !strings.Contains(string(body), `type="password"`) {
		t.Fatalf("short form: %d", res.StatusCode)
	}

	// 폼 제출 → 쿠키 → /{id} 가 목록, 파일 주소에도 쿠키가 실린다
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	r, err := c.PostForm(e.ts.URL+"/get", url.Values{"id": {id}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || r.Request.URL.Path != "/"+id || !strings.Contains(string(page), "photo.jpg") {
		t.Fatalf("login → short page: %d path=%s", r.StatusCode, r.Request.URL.Path)
	}
	r, err = c.Get(e.ts.URL + "/get/" + id + "/f/0")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(got) != "jpg" {
		t.Fatalf("download via cookie: %d %q", r.StatusCode, got)
	}

	// 비밀번호를 경로에 넣는 주소는 없다
	if res, _ := e.do("GET", "/"+id+"/"+pw, nil, nil); res.StatusCode != 404 {
		t.Fatalf("password-in-path must not exist: %d", res.StatusCode)
	}
	// 옛 주소는 새 주소로
	res, _ = e.do("GET", "/get/"+id, nil, nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/"+id {
		t.Fatalf("old get redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// 고정 경로·아이디 모양이 아닌 경로
	if res, _ := e.do("GET", "/static/style.css", nil, nil); res.StatusCode != 200 {
		t.Fatalf("static: %d", res.StatusCode)
	}
	if res, _ := e.do("GET", "/wp-login.php", nil, nil); res.StatusCode != 404 {
		t.Fatalf("bad id: %d", res.StatusCode)
	}
	if res, _ := e.do("GET", "/healthz", nil, nil); res.StatusCode != 200 {
		t.Fatalf("healthz shadowed: %d", res.StatusCode)
	}
}

func TestReservedIDsAndURL(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"admin", "api", "get", "static", "healthz"} {
		b, _ := json.Marshal(map[string]any{"files": files([2]any{"x", 1}), "id": id})
		if res, _ := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin); res.StatusCode != 400 {
			t.Fatalf("reserved %q: %d", id, res.StatusCode)
		}
	}
	_, body := e.do("POST", "/admin/api/tokens", strings.NewReader(`{"kind":"apikey","label":"k"}`), admin)
	var tok struct{ Secret string }
	json.Unmarshal(body, &tok)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("id", "report-1")
	fw, _ := mw.CreateFormFile("file", "r.txt")
	fw.Write([]byte("r"))
	mw.Close()
	res, body := e.do("POST", "/api/v1/drops", &buf, map[string]string{"Authorization": "Bearer " + tok.Secret, "Content-Type": mw.FormDataContentType()})
	var v map[string]any
	json.Unmarshal(body, &v)
	if res.StatusCode != 201 || v["url"] != e.ts.URL+"/report-1" {
		t.Fatalf("url: %d %v", res.StatusCode, v["url"])
	}
	if _, ok := v["share_url"]; ok {
		t.Fatal("share_url must not be returned")
	}
	if pw, _ := v["password"].(string); pw == "" || strings.Contains(v["url"].(string), pw) {
		t.Fatal("url must not contain the password")
	}
}
