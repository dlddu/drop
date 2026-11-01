FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/drop .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/drop /drop
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/drop"]
