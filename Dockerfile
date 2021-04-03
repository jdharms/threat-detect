FROM golang:alpine

WORKDIR /go/src/app
COPY . .

RUN apk --update upgrade && \
    apk add gcc && \
    apk add g++ && \
    apk add sqlite && \
    rm -rf /var/cache/apk/*

# TODO figure out database

ENV PORT 8080

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["server"]