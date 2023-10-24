# Builder
FROM whatwewant/builder-go:v1.20-1 as builder

WORKDIR /build

COPY go.mod ./

COPY go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 \
  go build \
  -trimpath \
  -ldflags '-w -s -buildid=' \
  -v -o socks5 ./cmd/socks5

# Server
FROM whatwewant/alpine:v3.17-1

LABEL MAINTAINER="Zero<tobewhatwewant@gmail.com>"

LABEL org.opencontainers.image.source="https://github.com/go-zoox/socks5"

ARG VERSION=latest

ENV MODE=production

COPY --from=builder /build/socks5 /bin

RUN socks5 --version

ENV VERSION=${VERSION}

CMD socks5 server
