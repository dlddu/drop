package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// 클러스터 안 서비스 계정 인증. 호출자는 파드에 projected 된 ServiceAccount 토큰(audience
// SA_TOKEN_AUDIENCE, 기본 "drop")을 Bearer 로 보내고, drop 은 apiserver TokenReview 로 확인한다.
// 기본 audience(apiserver) 토큰은 받지 않는다 — 그 토큰을 넘기면 받는 쪽이 호출자 행세를 할 수 있다.
// drop 의 ServiceAccount 에는 system:auth-delegator 가 필요하다(flux-cd-apps 가 부여).

var (
	ErrSAUnauthenticated = errors.New("service account token not authenticated")
	ErrSAUnavailable     = errors.New("token review unavailable")
)

// TokenReviewer 는 토큰을 "<namespace>/<serviceaccount>" 로 바꾼다.
type TokenReviewer interface {
	Review(ctx context.Context, token, audience string) (string, error)
}

const (
	saDir            = "/var/run/secrets/kubernetes.io/serviceaccount"
	saUsernamePrefix = "system:serviceaccount:"
)

// apiTokenReviewer 는 client-go 없이 in-cluster 설정으로 TokenReview 를 부른다.
type apiTokenReviewer struct {
	url       string
	tokenFile string
	client    *http.Client
}

// newInClusterReviewer 는 파드 안이 아니면 nil 을 돌려준다(교환 비활성).
func newInClusterReviewer() (TokenReviewer, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, nil
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("service account CA has no certificates")
	}
	return &apiTokenReviewer{
		url:       "https://" + net.JoinHostPort(host, port) + "/apis/authentication.k8s.io/v1/tokenreviews",
		tokenFile: saDir + "/token",
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

func (r *apiTokenReviewer) Review(ctx context.Context, token, audience string) (string, error) {
	// kubelet 이 자기 토큰을 갈아 끼우므로 매번 읽는다.
	own, err := os.ReadFile(r.tokenFile)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSAUnavailable, err)
	}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec":       map[string]any{"token": token, "audiences": []string{audience}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	req.Header.Set("Content-Type", "application/json")
	res, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSAUnavailable, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: tokenreview status %d", ErrSAUnavailable, res.StatusCode)
	}
	var tr struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", fmt.Errorf("%w: decode tokenreview: %v", ErrSAUnavailable, err)
	}
	return saFromReview(tr.Status.Authenticated, tr.Status.Audiences, tr.Status.User.Username, audience)
}

func saFromReview(authenticated bool, audiences []string, username, audience string) (string, error) {
	if !authenticated || !slices.Contains(audiences, audience) {
		return "", ErrSAUnauthenticated
	}
	rest, ok := strings.CutPrefix(username, saUsernamePrefix)
	if !ok {
		return "", ErrSAUnauthenticated
	}
	ns, name, ok := strings.Cut(rest, ":")
	if !ok || ns == "" || name == "" {
		return "", ErrSAUnauthenticated
	}
	return ns + "/" + name, nil
}
