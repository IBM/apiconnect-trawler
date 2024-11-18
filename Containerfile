FROM registry.access.redhat.com/ubi8/ubi-minimal
RUN microdnf update -y --refresh --best --nodocs --noplugins --setopt=install_weak_deps=0 && \
    microdnf install -y --refresh --best --nodocs --noplugins --setopt=install_weak_deps=0 zip unzip make git gcc && \
    microdnf install -y --refresh --best --nodocs --noplugins --setopt=install_weak_deps=0 go-toolset ca-certificates && \
    microdnf clean all && \
    rm -rf /var/cache/yum

ENV GOPATH /tmp/go
ENV PATH $PATH:$GOPATH/bin

COPY . .
RUN go mod download 

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./out/trawler .

FROM registry.access.redhat.com/ubi9/ubi-minimal

ARG USER_UID
ARG USER_NAME

ENV USER_UID ${USER_UID:-1001}
ENV USER_NAME ${USER_NAME:-apic}
RUN mkdir -p ${HOME} && chown ${USER_UID}:0 ${HOME} && chmod ug+rwx ${HOME}

COPY --from=build /app/out/trawler /app/trawler
COPY base-config.yaml /app/config/config.yaml

USER root
RUN microdnf upgrade -y --refresh --best --nodocs --noplugins --setopt=install_weak_deps=0 \
    && microdnf clean all
USER 1001:0

EXPOSE 63512
ENV CONFIG_PATH=/app/config/config.yaml

CMD ["/app/trawler"]
    