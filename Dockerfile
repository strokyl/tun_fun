FROM golang:1.10.3-alpine as build
RUN apk --no-cache add git && \
    go get -u github.com/kardianos/govendor

RUN mkdir -p /go/src/github.com/strokyl/tun_fun
WORKDIR /go/src/github.com/strokyl/tun_fun
COPY vendor/vendor.json vendor/vendor.json
RUN govendor sync

COPY main.go main.go
RUN CGO_ENABLED=0 GOOS=linux govendor build main.go

FROM alpine:3.7
COPY --from=build /go/src/github.com/strokyl/tun_fun/main /bin/tun_fun
ENTRYPOINT ["/bin/tun_fun"]