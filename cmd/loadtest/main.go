package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	paymentsv1 "authz-system/api"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type result struct {
	latency time.Duration
	ok      bool
}

func main() {
	var (
		addr        = flag.String("addr", "localhost:50051", "payments gRPC address")
		mode        = flag.String("mode", "charge", "charge|refund")
		n           = flag.Int("n", 5000, "total requests")
		c           = flag.Int("c", 50, "concurrency")
		timeout     = flag.Duration("timeout", 2*time.Second, "per-request timeout")
		warmup      = flag.Int("warmup", 200, "warmup requests (not included)")
		caPath      = flag.String("ca", "certs/ca.pem", "CA pem path")
		certPath    = flag.String("cert", "certs/orders.pem", "client cert pem path")
		keyPath     = flag.String("key", "certs/orders-key.pem", "client key pem path")
		serverName  = flag.String("servername", "payments", "TLS server name (must match payments cert)")
		printErrors = flag.Bool("print-errors", false, "print first errors")
	)
	flag.Parse()

	if *mode != "charge" && *mode != "refund" {
		log.Fatalf("invalid -mode=%s (expected charge|refund)", *mode)
	}
	if *n <= 0 || *c <= 0 {
		log.Fatalf("invalid -n or -c")
	}

	creds, err := mtlsCreds(*caPath, *certPath, *keyPath, *serverName)
	if err != nil {
		log.Fatalf("tls creds: %v", err)
	}

	conn, err := grpc.Dial(
		*addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := paymentsv1.NewPaymentsClient(conn)

	fmt.Printf("[*] loadtest addr=%s mode=%s n=%d c=%d warmup=%d timeout=%s\n",
		*addr, *mode, *n, *c, *warmup, timeout.String())

	// Warmup
	if *warmup > 0 {
		runWarmup(client, *mode, *warmup, *c, *timeout, *printErrors)
	}

	// Measured run
	results := make([]result, 0, *n)

	var okCount uint64
	var failCount uint64
	var errPrinted uint32

	start := time.Now()

	jobs := make(chan int, *c)
	out := make(chan result, *c)

	var wg sync.WaitGroup
	wg.Add(*c)
	for i := 0; i < *c; i++ {
		go func() {
			defer wg.Done()
			for range jobs {
				t0 := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				err := doCall(ctx, client, *mode)
				cancel()
				dt := time.Since(t0)

				r := result{latency: dt, ok: err == nil}
				if r.ok {
					atomic.AddUint64(&okCount, 1)
				} else {
					atomic.AddUint64(&failCount, 1)
					if *printErrors && atomic.CompareAndSwapUint32(&errPrinted, 0, 1) {
						fmt.Printf("[!] first error: %v\n", err)
					}
				}
				out <- r
			}
		}()
	}

	go func() {
		for i := 0; i < *n; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	for r := range out {
		results = append(results, r)
	}

	elapsed := time.Since(start)

	lat := make([]time.Duration, 0, len(results))
	for _, r := range results {
		lat = append(lat, r.latency)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

	p := func(q float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		// nearest-rank
		idx := int((q*float64(len(lat)) + 0.999999)) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(lat) {
			idx = len(lat) - 1
		}
		return lat[idx]
	}

	min := lat[0]
	max := lat[len(lat)-1]
	avg := avgDur(lat)

	rps := float64(len(results)) / elapsed.Seconds()

	fmt.Println()
	fmt.Printf("=== RESULTS (%s) ===\n", *mode)
	fmt.Printf("Requests: %d  Concurrency: %d\n", len(results), *c)
	fmt.Printf("OK: %d  FAIL: %d\n", okCount, failCount)
	fmt.Printf("Total time: %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("RPS: %.1f\n", rps)
	fmt.Println("Latency:")
	fmt.Printf("  min: %s\n", min)
	fmt.Printf("  avg: %s\n", avg)
	fmt.Printf("  p50: %s\n", p(0.50))
	fmt.Printf("  p95: %s\n", p(0.95))
	fmt.Printf("  p99: %s\n", p(0.99))
	fmt.Printf("  max: %s\n", max)

	fmt.Println()
	fmt.Println("Tip for analysis:")
	fmt.Println("- Compare p95/p99 growth when increasing -c (contention/queues).")
	fmt.Println("- Correlate with Prometheus: authz_policy_check_latency_seconds, authz_checks_total, policy_decisions_total.")
	fmt.Println("- Use 'docker stats' to see CPU/mem saturation (policy-server/payments).")
}

func runWarmup(client paymentsv1.PaymentsClient, mode string, warmup int, c int, timeout time.Duration, printErrors bool) {
	jobs := make(chan int, c)
	var wg sync.WaitGroup
	wg.Add(c)

	var errPrinted uint32

	for i := 0; i < c; i++ {
		go func() {
			defer wg.Done()
			for range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				err := doCall(ctx, client, mode)
				cancel()
				if err != nil && printErrors && atomic.CompareAndSwapUint32(&errPrinted, 0, 1) {
					fmt.Printf("[!] warmup first error: %v\n", err)
				}
			}
		}()
	}

	for i := 0; i < warmup; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func doCall(ctx context.Context, client paymentsv1.PaymentsClient, mode string) error {
	switch mode {
	case "charge":
		_, err := client.Charge(ctx, &paymentsv1.ChargeRequest{Amount: 100})
		return err
	case "refund":
		_, err := client.Refund(ctx, &paymentsv1.RefundRequest{Amount: 10})
		// В deny-сценарии ожидаем PermissionDenied — но в нагрузке мы считаем это "ok" или "fail"?
		// Для чистого измерения латентности пути deny можно считать это ok.
		// Если хочешь считать deny как ok — верни nil при PermissionDenied.
		return err
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}

func avgDur(a []time.Duration) time.Duration {
	if len(a) == 0 {
		return 0
	}
	var sum time.Duration
	for _, v := range a {
		sum += v
	}
	return sum / time.Duration(len(a))
}

func mtlsCreds(caPath, certPath, keyPath, serverName string) (credentials.TransportCredentials, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA PEM")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ServerName:   serverName,
	}

	return credentials.NewTLS(cfg), nil
}
