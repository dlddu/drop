# drop

최대 30일 보관하는 파일 전달 서비스. 받는 사람은 **아이디 + 비밀번호**만 있으면 됩니다.

운영: `https://drop.llkm.nl` (k3s, Flux — `flux-cd-apps/cluster/drop.yaml`)

## 누가 무엇을 하나

| 경로 | 누가 | 자격 |
|---|---|---|
| `/admin` | 관리자(올리기, 보관함 관리, 링크·API 키 발급) | Authelia 로그인 (Traefik forward-auth → `Remote-User`) |
| `/u/<token>` | 링크를 받은 누구나(올리기만) | 관리자가 발급한 임시 업로드 링크 — 유효 시간·사용 횟수·최대 보관일 |
| `/api/v1/*` | 서비스 계정(스크립트) | `Authorization: Bearer drk_…` API 키 |
| `/get` | 받는 사람 | 아이디 + 비밀번호 |

- 보관 기간은 올릴 때 1~30일 중 고르고(링크·키는 발급 때 정한 상한 이하), 지나면 받기에서 바로 사라지고 디스크에서도 지워집니다(웹 파드 10분 주기 + 매일 CronJob).
- 아이디·비밀번호는 비워 두면 자동으로 만들어집니다(비밀번호 6자 이상). 같은 아이디로 15분에 5번 틀리면 15분 잠깁니다.
- 파일 하나 2GB, 전체 20GB(환경 변수로 조정 — `config.go`).
- 브라우저 업로드는 16MB 조각으로 나눠 올리고, 끊기면 받은 위치부터 이어 올립니다(Traefik readTimeout 60초 대응).

## 받기

브라우저: `https://drop.llkm.nl/get` 에서 아이디·비밀번호 입력.

curl:

```sh
curl -u <아이디>:<비밀번호> -OJ https://drop.llkm.nl/get/<아이디>/f/0      # 첫 번째 파일
curl -u <아이디>:<비밀번호> -OJ https://drop.llkm.nl/get/<아이디>/all.zip   # 전부
```

## 서비스 계정 API

관리 화면 「링크·API 키」에서 키를 발급합니다(한 번만 보입니다).

```sh
# 작은 파일: multipart 한 번 (Traefik 60초 안에 끝나는 크기)
curl -H "Authorization: Bearer $DROP_KEY" \
  -F id=nightly-backup -F days=7 -F file=@dump.sql.gz \
  https://drop.llkm.nl/api/v1/drops
# → {"id":"nightly-backup","password":"…","url":"…","expires_at":"…",…}

curl -H "Authorization: Bearer $DROP_KEY" https://drop.llkm.nl/api/v1/drops            # 이 키로 올린 것
curl -H "Authorization: Bearer $DROP_KEY" -X DELETE https://drop.llkm.nl/api/v1/drops/<id>
```

큰 파일은 조각 API:

```
POST /api/v1/uploads                                {"files":[{"name","size"}],"id","password","days"}
                                                    → {"id","password","upload_key","chunk_bytes",…}
PUT  /api/v1/uploads/<id>/<key>/files/<n>?offset=N  본문 = 조각(최대 64MB). 409 면 {"received"} 부터 다시
GET  /api/v1/uploads/<id>/<key>/files/<n>           {"received","size"}
POST /api/v1/uploads/<id>/<key>/complete            보관함 열림(기간은 이때부터)
```

관리자·업로드 링크도 같은 API 를 `/admin/api`, `/u/<token>/api` 아래에서 씁니다(브라우저 쓰기 요청은 `X-Drop: 1` 헤더 필요 — CSRF 방어).

## 라우팅 경계 (중요)

`/admin*` 은 **반드시** forward-auth 라우트로만 들어와야 합니다. 앱은 `Remote-User` 헤더를 믿고, Traefik 공개 라우트는 이 헤더를 지웁니다(`flux-cd-apps/apps/drop/ingress-route.yaml`). 경로를 추가할 때 두 쪽을 같이 고치세요.

## 저장 구조

DB 없이 `DATA_DIR`(EFS PVC) 아래 파일로 둡니다: `drops/<id>/meta.json`, `drops/<id>/files/<n>`, `tokens/<sha256>.json`, `secret`(받기 쿠키 서명 키). 비밀번호는 PBKDF2-SHA256 해시, 토큰은 SHA-256 해시만 저장합니다. 쓰기 프로세스는 하나(`strategy: Recreate`, Sablier 0/1)라는 전제입니다.

## 개발

```sh
go test ./...
DATA_DIR=./tmp ADDR=:8080 go run .
# 관리자 화면 로컬 확인: Remote-User 헤더를 붙이는 프록시나 브라우저 확장 사용
```
