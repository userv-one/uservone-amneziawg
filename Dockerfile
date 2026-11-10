FROM golang:1.25.12 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=0.1.0
ARG COMMIT=dev
RUN RELEASE_VERSION="${VERSION#v}" && \
    LDFLAGS="-s -w -X github.com/userv-one/uservone-amneziawg/v3/buildinfo.Version=${RELEASE_VERSION} -X github.com/userv-one/uservone-amneziawg/v3/buildinfo.Commit=${COMMIT}" && \
    CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" \
    -o /usr/bin/uservone-amneziawg . && \
    CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" \
    -o /usr/bin/uservone-awg ./cmd/uservone-awg

FROM alpine:3.22 AS tools
ARG AWGTOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
RUN apk add --no-cache git build-base linux-headers && \
    git clone https://github.com/amnezia-vpn/amneziawg-tools.git /amneziawg-tools && \
    cd /amneziawg-tools && git checkout ${AWGTOOLS_COMMIT} && \
    cd src && make -j"$(nproc)"

FROM alpine:3.22
LABEL org.opencontainers.image.title="uservone-amneziawg" \
      org.opencontainers.image.source="https://github.com/userv-one/uservone-amneziawg" \
      org.opencontainers.image.description="Hardened AmneziaWG userspace core and profiles for userv.one"
RUN apk --no-cache add iproute2 iptables bash ca-certificates
COPY --from=tools /amneziawg-tools/src/wg /usr/bin/awg
COPY --from=tools /amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=build /usr/bin/uservone-amneziawg /usr/bin/uservone-amneziawg
COPY --from=build /usr/bin/uservone-awg /usr/bin/uservone-awg
RUN chmod +x /usr/bin/awg /usr/bin/awg-quick && \
    ln -s /usr/bin/uservone-amneziawg /usr/bin/amneziawg-go && \
    ln -s /usr/bin/awg /usr/bin/wg && \
    ln -s /usr/bin/awg-quick /usr/bin/wg-quick
