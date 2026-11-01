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

func TestShareLinks(t *testing.T) {
	e := newEnv(t)
	id, pw := e.upload("/admin/api", admin, map[string]any{
		"files": files([2]any{"photo.jpg", 3}), "id": "trip-photos", "password": "pa ss/한글",
	}, [][]byte{[]byte("jpg")}, 3)

	// /{id}: 아이디가 채워진 폼
	res, body := e.do("GET", "/"+id, nil, nil)
	if res.StatusCode != 200 || !strings.Contains(string(body), `value="trip-photos"`) || !strings.Contains(string(body), `type="password"`) {
		t.Fatalf("short form: %d", res.StatusCode)
	}

	// /{id}/{password}: 쿠키 → /{id} 로 보내고, 그 페이지는 목록
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	r, err := c.Get(e.ts.URL + "/" + id + "/" + url.PathEscape(pw))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || r.Request.URL.Path != "/"+id || !strings.Contains(string(page), "photo.jpg") {
		t.Fatalf("share login: %d path=%s", r.StatusCode, r.Request.URL.Path)
	}
	// 쿠키가 파일 주소에도 실린다
	r, err = c.Get(e.ts.URL + "/get/" + id + "/f/0")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(got) != "jpg" {
		t.Fatalf("download via share cookie: %d %q", r.StatusCode, got)
	}

	// 틀린 비밀번호: 401 폼, 비밀번호는 다시 보여 주지 않음
	res, body = e.do("GET", "/"+id+"/wrong-pass", nil, nil)
	if res.StatusCode != 401 || strings.Contains(string(body), "wrong-pass") {
		t.Fatalf("wrong share pw: %d", res.StatusCode)
	}
	// 옛 주소는 새 주소로
	res, _ = e.do("GET", "/get/"+id, nil, nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/"+id {
		t.Fatalf("old get redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// 고정 경로·잘못된 아이디는 공유 주소가 아니다
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

func TestReservedIDsAndShareURL(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"admin", "api", "get", "static", "healthz"} {
		b, _ := json.Marshal(map[string]any{"files": files([2]any{"x", 1}), "id": id})
		if res, _ := e.do("POST", "/admin/api/uploads", bytes.NewReader(b), admin); res.StatusCode != 400 {
			t.Fatalf("reserved %q: %d", id, res.StatusCode)
		}
	}
	res, body := e.do("POST", "/admin/api/tokens", strings.NewReader(`{"kind":"apikey","label":"k"}`), admin)
	var tok struct{ Secret string }
	json.Unmarshal(body, &tok)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("id", "report-1")
	mw.WriteField("password", "a/b c?d")
	fw, _ := mw.CreateFormFile("file", "r.txt")
	fw.Write([]byte("r"))
	mw.Close()
	res, body = e.do("POST", "/api/v1/drops", &buf, map[string]string{"Authorization": "Bearer " + tok.Secret, "Content-Type": mw.FormDataContentType()})
	var v DropView
	json.Unmarshal(body, &v)
	if res.StatusCode != 201 || v.URL != e.ts.URL+"/report-1" || v.ShareURL != e.ts.URL+"/report-1/a%2Fb%20c%3Fd" {
		t.Fatalf("share url: %d %+v", res.StatusCode, v)
	}
	// 그 링크가 실제로 열린다
	jar, _ := cookiejar.New(nil)
	r, err := (&http.Client{Jar: jar}).Get(v.ShareURL)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 || r.Request.URL.Path != "/report-1" {
		t.Fatalf("escaped share link: %d %s", r.StatusCode, r.Request.URL.Path)
	}
}
