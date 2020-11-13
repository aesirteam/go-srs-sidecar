FROM golang:1.13-alpine AS build

COPY . ${GOPATH}/src/go-srs-sidecar

RUN cd ${GOPATH}/src/go-srs-sidecar \
    && go mod vendor -v \
    && go build -mod=vendor -o bin/srs-sidecar


FROM alpine:3.12

ENV GIN_MODE release

COPY --from=build /go/src/go-srs-sidecar/bin/srs-sidecar /usr/bin/srs-sidecar

RUN  mkdir -p /app/conf /app/public

EXPOSE 8080

WORKDIR /app

ENTRYPOINT ["/usr/bin/srs-sidecar"]
CMD []