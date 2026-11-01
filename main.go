// drop: 최대 30일 보관하는 파일 전달 서비스.
//
// 올리기: Authelia 로 로그인한 관리자(/admin), 관리자가 발급한 임시 업로드 링크(/u/<token>),
// 서비스 계정 API 키(/api/v1). 받기: 아이디 + 비밀번호(/get, 또는 curl -u 아이디:비밀번호).
//
//	drop            웹 서버
//	drop cleanup    만료된 보관함·토큰을 지우고 끝낸다(CronJob 용)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(2)
	}
	st, err := OpenStore(cfg.DataDir)
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(1)
	}

	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		res, err := st.Cleanup(time.Now())
		if err != nil {
			slog.Error("cleanup", "err", err)
			os.Exit(1)
		}
		slog.Info("cleanup done", "drops", res.Drops, "tokens", res.Tokens)
		return
	}

	clearTemp(cfg.DataDir)
	srv, err := NewServer(cfg, st)
	if err != nil {
		slog.Error("server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go cleanupLoop(ctx, srv)

	hs := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout·WriteTimeout 은 두지 않는다: 큰 파일 내려받기가 끊긴다. 느린 요청은 Traefik 이 끊는다.
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	slog.Info("listening", "addr", cfg.Addr, "data", cfg.DataDir, "max_days", cfg.MaxDays)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
}

// cleanupLoop 은 깨어 있는 동안 10분마다 정리한다. Sablier 로 잠들어 있을 때는 CronJob 이 맡는다.
func cleanupLoop(ctx context.Context, s *Server) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		res, err := s.store.Cleanup(time.Now())
		if err != nil {
			slog.Error("cleanup", "err", err)
		} else if res.Drops+res.Tokens > 0 {
			slog.Info("cleanup", "drops", res.Drops, "tokens", res.Tokens)
		}
		s.idLimit.Sweep(time.Now())
		s.ipLimit.Sweep(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
