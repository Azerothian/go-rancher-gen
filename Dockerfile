FROM alpine:edge
MAINTAINER CausticLab

RUN apk add --no-cache ca-certificates

ENV RANCHER_GEN_RELEASE v0.4.3

ADD https://github.com/causticlab/go-rancher-gen/releases/download/${RANCHER_GEN_RELEASE}/rancher-gen-linux-amd64.tar.gz /tmp/rancher-gen.tar.gz
RUN tar -zxvf /tmp/rancher-gen.tar.gz -C /usr/local/bin \
	&& chmod +x /usr/local/bin/rancher-gen

ENTRYPOINT ["/usr/local/bin/rancher-gen"]
