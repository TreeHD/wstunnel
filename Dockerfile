FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go mod init wstunnel && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o wstunnel-go

FROM alpine:latest
RUN apk add --no-cache tzdata badvpn --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing
WORKDIR /app
COPY --from=builder /app/wstunnel-go .
COPY --from=builder /app/frontend ./frontend
COPY entrypoint.sh .
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

EXPOSE 80 443 9090 1080 7300
CMD ["./entrypoint.sh"]
