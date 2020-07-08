# Build Taiyue in a stock Go builder container
FROM golang:1.10-alpine as construction

RUN apk add --no-cache make gcc git musl-dev linux-headers

ADD . /taiyuechain
RUN cd /taiyuechain && make taiyue

# Pull Taiyue into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=construction /taiyuechain/build/bin/taiyue /usr/local/bin/
CMD ["taiyue"]

EXPOSE 8545 8545 30310 30310 30311 30311 30313 30313
ENTRYPOINT ["taiyue"]


