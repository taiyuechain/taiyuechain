# Build Geth in a stock Go builder container
FROM golang:1.10-alpine as construction

RUN apk add --no-cache make gcc musl-dev linux-headers

ADD . /taiyuechain
RUN cd /taiyuechain && make gtai

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=construction /taiyuechain/build/bin/gtai /usr/local/bin/
CMD ["gtai"]

EXPOSE 8545 8545 9215 9215 30310 30310 30311 30311 30313 30313
ENTRYPOINT ["gtai"]


