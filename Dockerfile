FROM golang:1.20-alpine as builder

WORKDIR /app

COPY ./server ./

RUN go mod download

RUN go build -o .

FROM alpine

WORKDIR /app

COPY --from=builder /app/analygits-server /app/analygits

EXPOSE 8080

CMD [ "/app/analygits" ]
