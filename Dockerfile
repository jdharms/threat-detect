FROM golang:alpine

RUN apk --update upgrade && \
    apk add gcc && \
    apk add g++ && \
    apk add sqlite && \
    rm -rf /var/cache/apk/*

ENV PORT 8080
ENV DB_PATH /app/data/database.db
VOLUME /app/data

WORKDIR /go/src/app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN go build -o server server.go

WORKDIR /dist
RUN cp /go/src/app/server /dist/server

EXPOSE ${PORT}
CMD ["/dist/server"]