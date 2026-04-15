package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	paymentsv1 "authz-system/api"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}

func envDefault(k, fallback string) string {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	return v
}

func mustClientTLSConfig(certFile, keyFile, caFile, serverName string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load cert/key: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		log.Fatalf("append ca failed")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName, // "payments"
	}
}

func mustClientCreds(certFile, keyFile, caFile, serverName string) credentials.TransportCredentials {
	return credentials.NewTLS(mustClientTLSConfig(certFile, keyFile, caFile, serverName))
}

func callREST(cmd string) {
	var path, label string
	switch cmd {
	case "rest-charge":
		path, label = "/payments/charge", "REST Charge"
	case "rest-refund":
		path, label = "/payments/refund", "REST Refund"
	default:
		log.Fatalf("unknown REST command %s", cmd)
	}

	tlsConfig := mustClientTLSConfig(
		mustEnv("CERT_FILE"),
		mustEnv("KEY_FILE"),
		mustEnv("CA_FILE"),
		"payments",
	)
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	baseURL := strings.TrimRight(envDefault("PAYMENTS_REST_URL", "https://payments:8080"), "/")
	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader([]byte("{}")))
	if err != nil {
		log.Fatalf("%s request error: %v", label, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("%s error: %v", label, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Fatalf("%s error: status=%d body=%s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Printf("%s OK: %s\n", label, strings.TrimSpace(string(body)))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: orders charge|refund|rest-charge|rest-refund")
		os.Exit(2)
	}
	cmd := os.Args[1]

	if cmd == "rest-charge" || cmd == "rest-refund" {
		callREST(cmd)
		return
	}

	creds := mustClientCreds(
		mustEnv("CERT_FILE"),
		mustEnv("KEY_FILE"),
		mustEnv("CA_FILE"),
		"payments",
	)

	conn, err := grpc.Dial("payments:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := paymentsv1.NewPaymentsClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	switch cmd {
	case "charge":
		resp, err := c.Charge(ctx, &paymentsv1.ChargeRequest{OrderId: "o-1", Amount: 100})
		if err != nil {
			log.Fatalf("Charge error: %v", err)
		}
		fmt.Println("Charge OK:", resp.Status)
	case "refund":
		resp, err := c.Refund(ctx, &paymentsv1.RefundRequest{PaymentId: "p-1", Amount: 50})
		if err != nil {
			log.Fatalf("Refund error: %v", err)
		}
		fmt.Println("Refund OK:", resp.Status)
	default:
		fmt.Println("usage: orders charge|refund|rest-charge|rest-refund")
		os.Exit(2)
	}
}
