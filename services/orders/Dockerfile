FROM golang:1.24-alpine AS build

WORKDIR /src
RUN apk add --no-cache protobuf git
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN protoc -I ./api \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  ./api/payments.proto

RUN go build -o /out/orders ./services/orders
RUN go build -o /out/transportbench ./cmd/transportbench

FROM alpine:3.19
WORKDIR /app
COPY --from=build /out/orders /app/orders
COPY --from=build /out/transportbench /app/transportbench
CMD ["sh", "-c", "sleep infinity"]
