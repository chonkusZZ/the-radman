# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV VERSION=$VERSION
RUN make manager nodes && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/dist/radman-manager /usr/local/bin/radman-manager
COPY --from=build /src/dist/nodes /opt/radman/nodes
COPY --from=build --chown=65532:65532 /out/data /data
ENV RADMAN_DATA=/data RADMAN_NODE_BIN_DIR=/opt/radman/nodes RADMAN_HTTPS_ADDR=:8443 RADMAN_HTTP_ADDR=:8080 RADMAN_UDP_ADDR=:7843
VOLUME /data
EXPOSE 8443/tcp 8080/tcp 7843/udp
ENTRYPOINT ["/usr/local/bin/radman-manager"]
