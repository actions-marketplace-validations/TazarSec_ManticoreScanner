ARG BASE_IMAGE=gcr.io/distroless/static-debian13:nonroot

FROM golang:1.26-bookworm AS builder

ARG VERSION=dev
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X github.com/TazarSec/ManticoreScanner/internal/buildinfo.Version=${VERSION}" \
    -o manticore ./cmd/manticore

FROM ${BASE_IMAGE}

COPY --from=builder /build/manticore /usr/local/bin/manticore

ENTRYPOINT ["manticore"]