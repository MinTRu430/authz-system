package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	paymentsv1 "authz-system/api"
	"authz-system/internal/authz"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type paymentsServer struct {
	paymentsv1.UnimplementedPaymentsServer
}

func (s *paymentsServer) Charge(ctx context.Context, req *paymentsv1.ChargeRequest) (*paymentsv1.ChargeReply, error) {
	return &paymentsv1.ChargeReply{Status: "charged"}, nil
}

func (s *paymentsServer) Refund(ctx context.Context, req *paymentsv1.RefundRequest) (*paymentsv1.RefundReply, error) {
	return &paymentsv1.RefundReply{Status: "refunded"}, nil
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}

func mustServerTLSConfig(certFile, keyFile, caFile string) *tls.Config {
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
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return tlsCfg
}

func mustServerCreds(certFile, keyFile, caFile string) credentials.TransportCredentials {
	return credentials.NewTLS(mustServerTLSConfig(certFile, keyFile, caFile))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	serviceName := mustEnv("SERVICE_NAME")
	policyURL := mustEnv("POLICY_URL")

	certFile := mustEnv("CERT_FILE")
	keyFile := mustEnv("KEY_FILE")
	caFile := mustEnv("CA_FILE")

	policyCert := mustEnv("POLICY_CERT_FILE")
	policyKey := mustEnv("POLICY_KEY_FILE")
	policyCA := mustEnv("POLICY_CA_FILE")

	// metrics endpoint
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Println("payments metrics on :9090")
		log.Fatal(http.ListenAndServe(":9090", mux))
	}()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	cfg := authz.Config{
		TargetService: serviceName,
		PolicyURL:     policyURL,
		FailOpen:      false,
		Timeout:       250 * time.Millisecond,
		CacheTTL:      2 * time.Second,
		PolicyClientTLS: authz.TLSFiles{
			CertFile: policyCert,
			KeyFile:  policyKey,
			CAFile:   policyCA,
		},
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /payments/charge", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"status": "charged"})
		})
		mux.HandleFunc("POST /payments/refund", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"status": "refunded"})
		})

		srv := &http.Server{
			Addr:      ":8080",
			Handler:   authz.NewHTTPMiddleware(cfg)(mux),
			TLSConfig: mustServerTLSConfig(certFile, keyFile, caFile),
		}
		log.Println("payments REST listening on :8080 (mTLS + authz)")
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}()

	s := grpc.NewServer(
		grpc.Creds(mustServerCreds(certFile, keyFile, caFile)),
		grpc.UnaryInterceptor(authz.NewUnaryInterceptor(cfg)),
		grpc.StreamInterceptor(authz.NewStreamInterceptor(cfg)),
	)

	paymentsv1.RegisterPaymentsServer(s, &paymentsServer{})

	log.Println("payments listening on :50051 (mTLS + authz)")
	log.Fatal(s.Serve(lis))
}
