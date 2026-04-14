FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
	&& addgroup -g 65532 -S keyrad \
	&& adduser -u 65532 -S -D -G keyrad -H -s /sbin/nologin keyrad \
	&& mkdir -p /app \
	&& chown keyrad:keyrad /app

WORKDIR /app

COPY build/amd64/keyrad /app/keyrad
RUN chown root:root /app/keyrad \
	&& chmod 0555 /app/keyrad

USER 65532:65532

EXPOSE 1812/udp

CMD ["/app/keyrad"]
