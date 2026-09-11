FROM golang@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install --no-install-recommends -y bpftool clang libbpf-dev llvm \
    && rm -rf /var/lib/apt/lists/*

RUN GOBIN=/usr/local/bin go install github.com/sigstore/cosign/v3/cmd/cosign@v3.1.2

WORKDIR /src
