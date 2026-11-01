package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// 단일 요청 업로드(API)의 임시 파일은 DATA_DIR/tmp 에 둔다 — 같은 파일 시스템이라 rename 으로 옮길
// 수 있고, 루트 파일 시스템은 읽기 전용이다. 남은 것은 기동 시 지운다.

func tmpRoot(dataDir string) string { return filepath.Join(dataDir, "tmp") }

func makeTempDir(dataDir string) (string, error) {
	if err := os.MkdirAll(tmpRoot(dataDir), 0o750); err != nil {
		return "", err
	}
	return os.MkdirTemp(tmpRoot(dataDir), "up-")
}

func removeAll(dir string) { _ = os.RemoveAll(dir) }

func saveTemp(dir string, n int, r io.Reader, maxBytes int64) (string, int64, error) {
	path := filepath.Join(dir, fmt.Sprint(n))
	f, err := os.Create(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	size, err := io.Copy(f, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return "", 0, fmt.Errorf("파일을 받지 못했습니다")
	}
	if size > maxBytes {
		return "", 0, fmt.Errorf("파일 하나는 %s까지입니다", humanBytes(maxBytes))
	}
	return path, size, nil
}

func moveInto(src, dst string) error { return os.Rename(src, dst) }

func clearTemp(dataDir string) { _ = os.RemoveAll(tmpRoot(dataDir)) }
