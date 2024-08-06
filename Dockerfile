ARG image

FROM registry.gitlab.com/security-products/${image} AS builder
# ENV http_proxy=192.168.31.87:19999 https_proxy=192.168.31.87:19999 
COPY . /works
WORKDIR /works
ENV PATH=$PATH:/root/.cargo/bin \
    RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup \
    RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup \
    RUSTFLAGS="-C target-feature=-crt-static" \
    PKG_CONFIG_PATH=/usr/bin/openssl

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
    apk add curl-dev curl libgcc && \
    apk add pkgconf gcc openssl-dev openssl clang15-libclang musl musl-dev && \
    curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y && \
    rustup target add x86_64-unknown-linux-musl && \
    env && \
    cargo build --release --target x86_64-unknown-linux-musl && \
    ls target/* && \
    mv /works/target/x86_64-unknown-linux-musl/release/sec_engine /works


FROM registry.gitlab.com/security-products/${image}

COPY --from=builder /works/sec_engine /usr/bin/sec_engine
RUN apk add musl-dev libgcc

