# syntax=docker/dockerfile:1
# The image the host commands run (email-me start): the gateway, with the
# host's configuration directory mounted at /config and the state volume at
# /data. The build stage runs natively and cross-compiles, so multi-platform
# images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/email-me ./cmd/email-me \
 && mkdir -p /out/root/data && chmod 1777 /out/root/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/email-me /usr/local/bin/email-me
# email-me start runs the container as the operator's own user, so it can
# write the configuration directory; a new volume inherits this mode, which
# lets that user write state.db.
COPY --from=build /out/root/ /
USER nonroot:nonroot
ENV EMAIL_ME_CONTAINER=1 EMAIL_ME_CONFIG_DIR=/config EMAIL_ME_DATA_DIR=/data
EXPOSE 8025 8026
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/email-me", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/email-me"]
CMD ["run", "--listen-all"]
