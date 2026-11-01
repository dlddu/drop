package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	KiB = int64(1) << 10
	MiB = KiB << 10
	GiB = MiB << 10
)

// Config 는 전부 환경 변수에서 온다. 기본값은 홈랩 운영 기준(PVC 20Gi, 파일당 2GB, 최대 30일).
type Config struct {
	Addr          string
	DataDir       string
	MaxFileBytes  int64    // 파일 하나의 최대 크기
	MaxTotalBytes int64    // 저장소 전체 한도(EFS 는 PVC 크기를 강제하지 않으므로 앱이 지킨다)
	MaxFiles      int      // 한 번에 올릴 수 있는 파일 수
	MaxDays       int      // 보관 기간 상한
	DefaultDays   int      // 보관 기간 기본값
	ChunkBytes    int64    // 브라우저 업로더가 쓰는 조각 크기(Traefik readTimeout 60s 안에 끝나야 한다)
	MaxChunkBytes int64    // 조각 하나의 서버 측 상한
	AdminGroups   []string // 비어 있으면 Authelia 로 로그인한 누구나 관리자
}

func LoadConfig() (Config, error) {
	c := Config{
		Addr:          env("ADDR", ":8080"),
		DataDir:       env("DATA_DIR", "/data"),
		MaxFileBytes:  2 * GiB,
		MaxTotalBytes: 20 * GiB,
		MaxFiles:      100,
		MaxDays:       30,
		DefaultDays:   7,
		ChunkBytes:    16 * MiB,
		MaxChunkBytes: 64 * MiB,
	}
	var err error
	if c.MaxFileBytes, err = envBytes("MAX_FILE_BYTES", c.MaxFileBytes); err != nil {
		return c, err
	}
	if c.MaxTotalBytes, err = envBytes("MAX_TOTAL_BYTES", c.MaxTotalBytes); err != nil {
		return c, err
	}
	if c.ChunkBytes, err = envBytes("CHUNK_BYTES", c.ChunkBytes); err != nil {
		return c, err
	}
	if c.MaxChunkBytes, err = envBytes("MAX_CHUNK_BYTES", c.MaxChunkBytes); err != nil {
		return c, err
	}
	if c.MaxFiles, err = envInt("MAX_FILES", c.MaxFiles); err != nil {
		return c, err
	}
	if c.MaxDays, err = envInt("MAX_DAYS", c.MaxDays); err != nil {
		return c, err
	}
	if c.DefaultDays, err = envInt("DEFAULT_DAYS", c.DefaultDays); err != nil {
		return c, err
	}
	for _, g := range strings.Split(os.Getenv("ADMIN_GROUPS"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			c.AdminGroups = append(c.AdminGroups, g)
		}
	}
	switch {
	case c.MaxDays < 1:
		return c, fmt.Errorf("MAX_DAYS must be >= 1")
	case c.DefaultDays < 1 || c.DefaultDays > c.MaxDays:
		return c, fmt.Errorf("DEFAULT_DAYS must be within 1..MAX_DAYS")
	case c.ChunkBytes < 1 || c.ChunkBytes > c.MaxChunkBytes:
		return c, fmt.Errorf("CHUNK_BYTES must be within 1..MAX_CHUNK_BYTES")
	case c.MaxFiles < 1:
		return c, fmt.Errorf("MAX_FILES must be >= 1")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

// envBytes 는 "2147483648", "2GiB", "512MiB", "64KiB" 를 받는다.
func envBytes(k string, def int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def, nil
	}
	mult := int64(1)
	for _, s := range []struct {
		suf string
		m   int64
	}{{"GiB", GiB}, {"MiB", MiB}, {"KiB", KiB}} {
		if strings.HasSuffix(v, s.suf) {
			mult, v = s.m, strings.TrimSuffix(v, s.suf)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: invalid byte size", k)
	}
	return n * mult, nil
}
