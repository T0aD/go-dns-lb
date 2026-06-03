package main

import (
	"flag"
	"fmt"
//	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	totalReqs   int64
	successReqs int64
	failedReqs  int64
)

func main() {
	var (
		port      int
		forks     int
		threads   int
		total     int
		queryType string
		protocol  string
		timeout   time.Duration
	)

	flag.IntVar(&port, "port", 53, "DNS server port")
	flag.IntVar(&forks, "forks", 1, "Number of fork groups (multiplied with threads)")
	flag.IntVar(&threads, "threads", 1, "Number of goroutines per fork")
	flag.IntVar(&total, "total", 1000, "Total number of requests")
	flag.StringVar(&queryType, "type", "A", "DNS query type (A, AAAA, MX, TXT, etc.)")
	flag.StringVar(&protocol, "protocol", "udp", "Transport protocol (udp or tcp)")
	flag.DurationVar(&timeout, "timeout", 2*time.Second, "Timeout per request")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <server> <domain>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	serverHost := args[0]
	domain := args[1]
	server := fmt.Sprintf("%s:%d", serverHost, port)

	// Validation protocole
	if protocol != "udp" && protocol != "tcp" {
		fmt.Fprintf(os.Stderr, "Error: protocol must be 'udp' or 'tcp'\n")
		os.Exit(1)
	}

	// Résolution du type de requête
	qtype, ok := dns.StringToType[queryType]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: unknown query type '%s'\n", queryType)
		os.Exit(1)
	}

	workers := forks * threads
	reqsPerWorker := total / workers
	remainder := total % workers

	fmt.Printf("=== DNS Benchmark ===\n")
	fmt.Printf("Server:       %s (%s)\n", server, protocol)
	fmt.Printf("Domain:       %s (type %s)\n", domain, queryType)
	fmt.Printf("Total reqs:   %d\n", total)
	fmt.Printf("Concurrency:  %d workers (%d forks × %d threads)\n", workers, forks, threads)
	fmt.Printf("Timeout:      %v\n\n", timeout)

	startTime := time.Now()

	latencies := make(chan time.Duration, total)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		reqCount := reqsPerWorker
		if i < remainder {
			reqCount++ // Répartit le reste équitablement
		}
		go func(workerID int, count int) {
			defer wg.Done()

			// Client DNS dédié par worker (évite le contention)
			client := &dns.Client{
				Net:     protocol,
				Timeout: timeout,
			}

			for j := 0; j < count; j++ {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(domain), qtype)
				msg.RecursionDesired = true

				reqStart := time.Now()
				_, _, err := client.Exchange(msg, server)
				reqDuration := time.Since(reqStart)

				atomic.AddInt64(&totalReqs, 1)
				if err != nil {
					atomic.AddInt64(&failedReqs, 1)
				} else {
					atomic.AddInt64(&successReqs, 1)
					latencies <- reqDuration
				}
			}
		}(i, reqCount)
	}

	wg.Wait()
	close(latencies)

	totalDuration := time.Since(startTime)

	// Collecte & tri des latences
	var latSlice []time.Duration
	for lat := range latencies {
		latSlice = append(latSlice, lat)
	}
	sort.Slice(latSlice, func(i, j int) bool { return latSlice[i] < latSlice[j] })

	// Statistiques globales
	tr := atomic.LoadInt64(&totalReqs)
	sr := atomic.LoadInt64(&successReqs)
	fr := atomic.LoadInt64(&failedReqs)

	fmt.Println("=== Results ===")
	fmt.Printf("  Time taken for tests:    %.3f seconds\n", totalDuration.Seconds())
	fmt.Printf("  Complete requests:       %d\n", tr)
	fmt.Printf("  Successful requests:     %d\n", sr)
	fmt.Printf("  Failed requests:         %d\n", fr)
	if fr > 0 {
		fmt.Printf("  Failure rate:            %.2f%%\n", float64(fr)/float64(tr)*100)
	}
	fmt.Printf("  Requests per second:     %.2f [#/sec] (mean)\n", float64(tr)/totalDuration.Seconds())
	if tr > 0 {
		fmt.Printf("  Time per request:        %.3f [ms] (mean)\n", float64(totalDuration.Microseconds())/float64(tr)/1000)
		fmt.Printf("  Time per request:        %.3f [ms] (mean, across all concurrent requests)\n",
			float64(totalDuration.Microseconds())/float64(tr)/float64(workers)/1000)
	}

	// Percentiles
	if len(latSlice) > 0 {
		percentile := func(p float64) time.Duration {
			idx := int(float64(len(latSlice)) * p)
			if idx >= len(latSlice) {
				idx = len(latSlice) - 1
			}
			return latSlice[idx]
		}

		fmt.Println("\n=== Latency Percentiles (successful requests) ===")
		fmt.Printf("  Min:   %v\n", latSlice[0])
		fmt.Printf("  P50:   %v\n", percentile(0.50))
		fmt.Printf("  P75:   %v\n", percentile(0.75))
		fmt.Printf("  P90:   %v\n", percentile(0.90))
		fmt.Printf("  P95:   %v\n", percentile(0.95))
		fmt.Printf("  P98:   %v\n", percentile(0.98))
		fmt.Printf("  P99:   %v\n", percentile(0.99))
		fmt.Printf("  Max:   %v (longest request)\n", latSlice[len(latSlice)-1])
	}

	// Transfert réseau estimé
	bytesPerReq := 60 // estimation basse (header DNS + question)
	totalBytes := tr * int64(bytesPerReq)
	fmt.Printf("\n=== Network ===\n")
	fmt.Printf("  Bytes transferred:       ~%.2f KB\n", float64(totalBytes)/1024)
	fmt.Printf("  Throughput:              %.2f KB/s\n", float64(totalBytes)/1024/totalDuration.Seconds())
}
