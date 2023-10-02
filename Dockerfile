# syntax=docker/dockerfile:1.6

ARG ALPINE_VERSION="3.18"
ARG GOLANG_VERSION="1.21"
ARG GOLANG_IMAGE="golang:${GOLANG_VERSION}-alpine"

# =============================================================================
FROM ${GOLANG_IMAGE} as builder

SHELL ["/bin/ash", "-e", "-u" ,"-o", "pipefail", "-o", "errexit", "-o", "nounset", "-c"]

RUN <<'EOF'
apk add --no-cache \
    make \
    automake \
    alpine-sdk \
    libc6-compat \
    softhsm \
    autoconf \
    libtool \
    libseccomp-dev \
    cmake \
    p11-kit-dev \
    openssl-dev \
    stunnel
rm -rf /var/cache/apk/*
EOF

WORKDIR /tmp/aws-rolesanywhere-credential-helper

ENV CGO_ENABLED=1 \
    GOOS=linux \
    GO111MODULE=on

COPY . .

RUN <<'EOF'
make release
mv build/bin/aws_signing_helper /
chmod +x /aws_signing_helper
EOF

# =============================================================================
FROM alpine:${ALPINE_VERSION} as release

SHELL ["/bin/ash", "-e", "-u" ,"-o", "pipefail", "-o", "errexit", "-o", "nounset", "-c"]

RUN <<'EOF'
apk add --no-cache libc6-compat openssl
rm -rf /var/cache/apk/*
rm -rf /tmp/*
EOF

COPY --from=builder /aws_signing_helper /usr/local/bin/aws_signing_helper

ENTRYPOINT [ "/usr/local/bin/aws_signing_helper" ]
