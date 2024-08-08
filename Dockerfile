ARG image

FROM registry.gitlab.com/security-products/${image} AS builder
# FROM rust:latest as builder
# ENV http_proxy=192.168.31.87:19999 https_proxy=192.168.31.87:19999 
COPY . /works
WORKDIR /works
ENV RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup \
    RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup 

RUN [ -n "$(which apk)" ] && ( \
        sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
        # skip libssl1.1 
        apk add curl-dev curl libgcc libssl3 && \
        apk add pkgconf gcc openssl-dev openssl clang15-libclang musl musl-dev perl make linux-headers && \
        export PKG_CONFIG_PATH=/usr/bin/pkgconf \
    ) || ( \
        # sed -i 's#http://deb.debian.org#https://mirrors.ustc.edu.cn#g' /etc/apt/sources.list && \
        # sed -i 's|security.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' /etc/apt/sources.list && \
        apt update -y && \
        apt install gcc libssl-dev pkg-config libclang-15-dev make wget musl musl-dev musl-tools -y && \
        export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig \
    )

RUN cd ~ && \
    # wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
    wget https://github.com/openssl/openssl/releases/download/openssl-3.3.1/openssl-3.3.1.tar.gz && \
    tar xvf openssl-3.3.1.tar.gz && cd openssl-3.3.1 && \
    ./config --prefix=/usr/local/share/openssl && \
    make -j4 && make install -j4 && \
    export OPENSSL_DIR=/usr/local/share/openssl 

RUN cd /works && \
    curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y && \
    export PATH=$PATH:$HOME/.cargo/bin && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl && \
    mv /works/target/x86_64-unknown-linux-musl/release/sec_engine /works

FROM registry.gitlab.com/security-products/${image}

COPY --from=builder /works/sec_engine /usr/bin/sec_engine
RUN [ -n "$(which apk)" ] && ( \
        apk add libgcc \
    ) || ( \
        apt update && \
        apt install musl -y \
    )

