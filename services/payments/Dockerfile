FROM golang:1.24.11-alpine3.22 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o /out/payments ./services/payments

FROM alpine:3.22.2
WORKDIR /app
COPY --from=build /out/payments /app/payments
EXPOSE 50051 9090
CMD ["/app/payments"]
