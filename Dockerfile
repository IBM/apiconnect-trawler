FROM registry.access.redhat.com/ubi9/ubi:latest AS build

WORKDIR /app/

RUN dnf upgrade --assumeyes
RUN dnf install -y curl jq tar git --allowerasing
COPY . .
# Set the Go version dynamically by fetching the latest version
RUN GOVERSION=$(egrep "^toolchain " go.mod | awk -Fgo '{print $2}') && \
    echo "Installing Go version: $GOVERSION" && \
    curl -sSL "https://golang.org/dl/go$GOVERSION.linux-amd64.tar.gz" | tar -C /usr/local -xzf - && \
    ln -s /usr/local/go/bin/go /usr/bin/go

RUN go mod download 

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./out/trawler -ldflags="-X 'main.Version=$(git describe --tags)' -X 'main.BuildTime=$(date +%Y%m%dT%H%M)'" .
RUN dnf install ca-certificates --assumeyes
RUN groupadd -r app && useradd -r -g app app

FROM scratch

COPY --from=build /app/out/trawler /app/trawler
COPY base-config.yaml /app/config/config.yaml
COPY --from=build /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /etc/passwd /etc/passwd

USER app

EXPOSE 63512

CMD ["/app/trawler", "-c", "/app/config/config.yaml"]
