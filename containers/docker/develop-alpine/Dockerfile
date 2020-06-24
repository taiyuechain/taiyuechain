FROM alpine:3.7

RUN \
  apk add --update go git make gcc musl-dev linux-headers ca-certificates && \
  git clone --depth 1 https://github.com/taiyuechain/taiyuechain && \
  (cd taiyuechain && make taiyue) && \
  cp taiyuechain/build/bin/taiyue /taiyue && \
  apk del go git make gcc musl-dev linux-headers && \
  rm -rf /taiyuechain && rm -rf /var/cache/apk/*

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/taiyue"]
