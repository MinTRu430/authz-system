FROM golang:1.24.11-alpine3.22 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o /out/orders ./services/orders
RUN go build -o /out/transportbench ./cmd/transportbench

FROM alpine:3.22.2
WORKDIR /app
COPY --from=build /out/orders /app/orders
COPY --from=build /out/transportbench /app/transportbench
CMD ["sh", "-c", "sleep infinity"]
