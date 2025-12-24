FROM golang:1.24-alpine AS build
WORKDIR /src
COPY ../go.mod ../go.sum ./
RUN go mod download
COPY .. .
RUN go build -o /out/policy-server ./policy-server

FROM alpine:3.19
WORKDIR /app
COPY --from=build /out/policy-server /app/policy-server
EXPOSE 8443
CMD ["/app/policy-server"]
