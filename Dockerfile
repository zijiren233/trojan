FROM alpine

COPY . trojan
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    cmake \
    boost-dev \
    openssl-dev \
    curl-dev \
    && (cd trojan && cmake . -DENABLE_V2BOARD=ON -DENABLE_NAT=ON -DENABLE_REUSE_PORT=ON -DENABLE_SSL_KEYLOG=OFF -DSYSTEMD_SERVICE=OFF && cmake --build . -- -j $(nproc) && strip -s trojan \
    && mv trojan /usr/local/bin) \
    && rm -rf trojan \
    && apk del .build-deps \
    && apk add --no-cache --virtual .trojan-rundeps \
    libstdc++ \
    boost-system \
    boost-program_options \
    libcurl

WORKDIR /config

ENTRYPOINT [ "trojan" ]

CMD ["-c", "config.json"]
