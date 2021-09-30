FROM golang:alpine AS builder
WORKDIR /go/src/github.com/wzshiming/sshproxy/
COPY . .
ENV CGO_ENABLED=0
RUN go install ./cmd/sshproxy

FROM alpine
EXPOSE 8080
COPY --from=builder /go/bin/sshproxy /usr/local/bin/
ENTRYPOINT [ "/usr/local/bin/sshproxy" ]
