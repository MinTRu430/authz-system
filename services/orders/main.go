package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
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

func mustClientCreds(certFile, keyFile, caFile, serverName string) credentials.TransportCredentials {
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
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName, // "payments"
	})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: orders charge|refund")
		os.Exit(2)
	}
	cmd := os.Args[1]

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
		fmt.Println("usage: orders charge|refund")
		os.Exit(2)
	}
}
