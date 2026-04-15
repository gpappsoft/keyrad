# Copyright 2026 Marco Moenig <marco@sec73.io>

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

### build stage
###
FROM cgr.dev/chainguard/wolfi-base AS builder

ENV LANG=C.UTF-8

RUN apk add --no-cache ca-certificates git go

ARG VERSION=main

WORKDIR /src
RUN git clone --depth 1 --branch ${VERSION} https://github.com/gpappsoft/keyrad.git . \
	&& go mod download \
	&& CGO_ENABLED=0 go build -v -o /app/keyrad .

### final stage
###
FROM cgr.dev/chainguard/wolfi-base

LABEL maintainer="Marco Moenig <marco.moenig@sec73.io>"
LABEL org.opencontainers.image.source="https://github.com/gpappsoft/keyrad.git"
LABEL org.opencontainers.image.url="https://github.com/gpappsoft/keyrad.git"
LABEL org.opencontainers.image.description="A Go-based RADIUS server that authenticates users against Keycloak, supporting password and OTP (TOTP) flows."


WORKDIR /app

COPY --from=builder /app/keyrad /app/keyrad
RUN chown root:root /app/keyrad \
	&& chmod 0555 /app/keyrad

USER 65532:65532

EXPOSE 1812/udp

CMD ["/app/keyrad"]
