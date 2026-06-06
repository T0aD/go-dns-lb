package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	// TCP mode:
	"encoding/binary"
	"io"

	// DNS responses:
	"github.com/miekg/dns"

	// fetch counter value
	"github.com/prometheus/client_golang/prometheus/testutil"

	// for stats dump
	"encoding/json"
	"bytes"

)


type CacheEntry struct {
	Response *dns.Msg
	ExpiresAt time.Time
}

const (
	healthInterval = 10 * time.Second
	healthTimeout  = 2 * time.Second
	forwardTimeout = 5 * time.Second
	tcpIdleTimeout = 5 * time.Second
	maxFailBeforeDown = 3 // number of maximum checks to fail before being marked as down
)

var (
	backends     []string
	healthy      = make(map[string]bool)
	failCount    = make(map[string]int)
	mu           sync.RWMutex
	currentIndex uint32
	debugMode    bool
	metricsPort  int
	logFile      string

	// Caches DNS
	positiveCache = make(map[string]*CacheEntry)
	negativeCache = make(map[string]*CacheEntry)
	cacheMu       sync.RWMutex
	
	// Configuration cache
	enablePositiveCache bool
	enableNegativeCache bool
	positiveCacheTTL    time.Duration
	negativeCacheTTL    time.Duration

	// failures management
	failureCounts   = make(map[string]int)
	failureCountsMu sync.Mutex
	failureThreshold = 3

	cacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_cache_hits_total",
			Help: "Number of cache hits",
		},
		[]string{"cache_type"}, // "positive" ou "negative"
	)
	cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_cache_misses_total",
			Help: "Number of cache misses",
		},
	)
	cacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dns_lb_cache_size",
			Help: "Current number of entries in cache",
		},
		[]string{"cache_type"},
	)

	emptyAnswersTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_empty_answers_total",
			Help: "Number of NOERROR responses with 0 records in Answer section",
		},
		[]string{"backend"},
	)

	// stats
	clientStats = make(map[string]*atomic.Int64)
	clientStatsMu sync.RWMutex
	statsFilePath = "/var/log/dns-lb/client-stats.json"

	// zombie check
	zombieCheckDomain string

	appVersion = "260605-zombie"
)

// buffer pool to use during runUDPServer
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4096)
		return &b
	},
}

/*
var dnsProbe = []byte{
	0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	0x00, 0x01, 0x00, 0x01,
}
*/
var dnsProbe []byte


// 📊 Prometheus Metrics
var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "dns_lb_requests_total", Help: "Total DNS requests processed"},
		[]string{"backend", "status"},
	)
	responseDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_lb_response_duration_seconds",
			Help:    "Time taken to forward and receive response",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"backend"},
	)
	backendHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "dns_lb_backend_health", Help: "Backend health (1=up, 0=down)"},
		[]string{"backend"},
	)
	activeBackends = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "dns_lb_active_backends", Help: "Number of healthy backends"},
	)
	errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "dns_lb_errors_total", Help: "Total errors by type"},
		[]string{"type"},
	)

	malformedPackets = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "dns_lb_malformed_packets_total", Help: "Invalid/short packets dropped"},
	)
	
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dns_lb_build_info",
			Help: "Build information (version, commit, go version) exposed as a constant 1.",
		},
		[]string{"version"},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal, responseDuration, backendHealth, activeBackends, errorsTotal, malformedPackets, emptyAnswersTotal)
	prometheus.MustRegister(cacheHits, cacheMisses, cacheSize, buildInfo)

	buildInfo.WithLabelValues(appVersion).Set(1)
}


func incrementFailureCount(addr string) {
    failureCountsMu.Lock()
    defer failureCountsMu.Unlock()
    failureCounts[addr]++
}

func getFailureCount(addr string) int {
    failureCountsMu.Lock()
    defer failureCountsMu.Unlock()
    return failureCounts[addr]
}

func resetFailureCount(addr string) {
    failureCountsMu.Lock()
    defer failureCountsMu.Unlock()
    failureCounts[addr] = 0
}

func setHealthy(addr string, status bool) {
	mu.Lock()
	
	var becameHealthy bool
	var becameUnhealthy bool
	
	if status {
		failCount[addr] = 0
		if !healthy[addr] {
			healthy[addr] = true
			becameHealthy = true
			log.Printf("✅ Backend %s is now UP", addr)
		}
	} else {
		failCount[addr]++
		if healthy[addr] && failCount[addr] >= maxFailBeforeDown {
			healthy[addr] = false
			becameUnhealthy = true
			log.Printf("❌ Backend %s is now DOWN (after %d consecutive failures)", addr, failCount[addr])
		}
	}
	
	mu.Unlock() // ← Libérer le lock AVANT d'appeler updateActiveBackendsMetric
	
	// Mettre à jour les métriques Prometheus (hors du lock)
	if becameHealthy {
		backendHealth.WithLabelValues(addr).Set(1)
		updateActiveBackendsMetric()
	} else if becameUnhealthy {
		backendHealth.WithLabelValues(addr).Set(0)
		updateActiveBackendsMetric()
	}
}


func updateActiveBackendsMetric() {
	mu.RLock()
	count := 0
	for _, h := range healthy {
		if h {
			count++
		}
	}
	mu.RUnlock()
	activeBackends.Set(float64(count))
}

func healthcheck(ctx context.Context) {

	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var wg sync.WaitGroup
			for _, addr := range backends {
				wg.Add(1)
				go func(backendAddr string) {
					defer wg.Done()
					checkBackend(addr)
				}(addr)

			}
			wg.Wait()
		}
	}
}


func checkBackend(addr string) {
	// get current status
	isCurrentlyDown := func() bool {
		mu.RLock()
		defer mu.RUnlock()
		return !healthy[addr] 
	}

	conn, err := net.DialTimeout("udp", addr, healthTimeout)
	if err != nil {
		if !isCurrentlyDown() {
			incrementFailureCount(addr)
			log.Printf("⚠️  Backend %s couldnt UDP connect. Marking DOWN. %d/%d", addr, getFailureCount(addr), failureThreshold)
			setHealthy(addr, false)
		}
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(healthTimeout))
	if _, err := conn.Write(dnsProbe); err != nil {
		if !isCurrentlyDown() {
			incrementFailureCount(addr)
			log.Printf("⚠️  Backend %s couldnt write to UDP. Marking DOWN. %d/%d", addr, getFailureCount(addr), failureThreshold)
			setHealthy(addr, false)
		}
		return
	}

	conn.SetReadDeadline(time.Now().Add(healthTimeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		if !isCurrentlyDown() {
			incrementFailureCount(addr)
			log.Printf("⚠️  Backend %s couldnt read from UDP. Marking DOWN. %d/%d", addr, getFailureCount(addr), failureThreshold)
			setHealthy(addr, false)
		}
		return
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		if !isCurrentlyDown() {
			incrementFailureCount(addr)
			log.Printf("⚠️  Backend %s couldnt unpack server response. Marking DOWN. %d/%d", addr, getFailureCount(addr), failureThreshold)
			setHealthy(addr, false)
		}
		return
	}

	if resp.Rcode == dns.RcodeServerFailure || 
		resp.Rcode == dns.RcodeRefused ||
		resp.Rcode == dns.RcodeNameError ||
		resp.Rcode == dns.RcodeNotImplemented {
		if !isCurrentlyDown() {
			incrementFailureCount(addr)
			log.Printf("⚠️  Backend %s returned error RCODE %d %s . Marking DOWN. %d/%d", addr, resp.Rcode, dns.RcodeToString[resp.Rcode], getFailureCount(addr), failureThreshold)
			setHealthy(addr, false)
		}
		return
	}

	// Empty answer but success
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
		if !isCurrentlyDown() {
			incrementFailureCount(addr)
			log.Printf("⚠️  Backend %s returned NOERROR but EMPTY answer (DB down?). Marking DOWN. %d/%d", addr, getFailureCount(addr), failureThreshold)
			setHealthy(addr, false)
		}
		return
	}

	// ✅ Succès : marquer comme sain
	if isCurrentlyDown() {
		resetFailureCount(addr)
		setHealthy(addr, true)
	}
}


func getHealthyBackend() string {
	mu.RLock()
	defer mu.RUnlock()

	// 1. Essayer de trouver un backend sain
	var candidates []string
	for _, addr := range backends {
		if healthy[addr] {
			candidates = append(candidates, addr)
		}
	}

	if len(candidates) > 0 {
		// Round-robin parmi les backends sains
		idx := atomic.AddUint32(&currentIndex, 1)
		return candidates[idx%uint32(len(candidates))]
	}

	// 2. MODE DÉGRADÉ : si tous sont DOWN, essayer quand même (round-robin sur tous)
	// Cela évite le blocage total quand le healthcheck est trop pessimiste
	if len(backends) > 0 {
		log.Printf("⚠️  No healthy backend, fallback to degraded mode (trying all backends)")
		idx := atomic.AddUint32(&currentIndex, 1)
		return backends[idx%uint32(len(backends))]
	}

	return ""
}


/* Cache functions */

// Génère une clé unique pour la requête (domaine + type)
func getCacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.Qtype)
}

// Vérifie si une entrée est encore valide
func isCacheValid(entry *CacheEntry) bool {
	return time.Now().Before(entry.ExpiresAt)
}


// display stats regularly
func displayStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		logCacheMetrics()
	}
}

func regularDumpClientStats() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("📥  triggering client stats dump...")
		dumpClientStats()
	}
}


func logCacheMetrics() {
	// Extraire les valeurs des compteurs/gauges
	posHits := testutil.ToFloat64(cacheHits.WithLabelValues("positive"))
	negHits := testutil.ToFloat64(cacheHits.WithLabelValues("negative"))
	misses := testutil.ToFloat64(cacheMisses)
	posSize := testutil.ToFloat64(cacheSize.WithLabelValues("positive"))
	negSize := testutil.ToFloat64(cacheSize.WithLabelValues("negative"))
	
	// Calculer le hit ratio
	totalHits := posHits + negHits
	hitRatio := 0.0
	if totalHits+misses > 0 {
		hitRatio = (totalHits / (totalHits + misses)) * 100
	}

	mu.RLock()
	upCount := 0
	for _, addr := range backends {
		if healthy[addr] { upCount++ }
	}
	mu.RUnlock()


	// Séparer succès/erreurs
	successReqs := 0.0
	errorReqs := 0.0
	
	// Parcourir tous les labels pour agréger
	mu.RLock()
	for _, addr := range backends {
		successReqs += testutil.ToFloat64(requestsTotal.WithLabelValues(addr, "success"))
		errorReqs += testutil.ToFloat64(requestsTotal.WithLabelValues(addr, "error"))
	}
	mu.RUnlock()
	
	// 🚀 Stats globales des requêtes
	totalReqs := successReqs + errorReqs

	log.Printf("📊 Global: total=%.0f success=%.0f errors=%.0f | Cache: pos_hits=%.0f neg_hits=%.0f misses=%.0f | size: pos=%.0f neg=%.0f | hit_ratio=%.1f%% | backends: %d/%d UP",
		totalReqs, successReqs, errorReqs, posHits, negHits, misses, posSize, negSize, hitRatio, upCount, len(backends))
}


// Nettoie les entrées expirées (appelé périodiquement)
func cleanExpiredCache() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		cacheMu.Lock()
		now := time.Now()
		
		// Nettoyer le cache positif
		for key, entry := range positiveCache {
			if now.After(entry.ExpiresAt) {
				delete(positiveCache, key)
			}
		}
		cacheSize.WithLabelValues("positive").Set(float64(len(positiveCache)))
		
		// Nettoyer le cache négatif
		for key, entry := range negativeCache {
			if now.After(entry.ExpiresAt) {
				delete(negativeCache, key)
			}
		}
		cacheSize.WithLabelValues("negative").Set(float64(len(negativeCache)))
		
		cacheMu.Unlock()
	}
}


func forwardRequest(conn *net.UDPConn, buf []byte, n int, client *net.UDPAddr) {
	start := time.Now()

	// 🚀 Incrémenter le compteur IP (ultra-rapide)
	incrementClientStat(client.IP.String())
	
	req := new(dns.Msg)
	if err := req.Unpack(buf[:n]); err != nil {
		errorsTotal.WithLabelValues("unpack_fail").Inc()
		return
	}

	// 🚀 DEBUG RESTAURÉ (et simplifié grâce au parsing miekg/dns)
	if debugMode && len(req.Question) > 0 {
		q := req.Question[0]
		qtype := dns.TypeToString[q.Qtype]
		if qtype == "" { qtype = fmt.Sprintf("TYPE%d", q.Qtype) }
		log.Printf("[DEBUG] UDP Query from %s: %s %s", client.String(), q.Name, qtype)
	}

	resp, target, isHit, err := resolveRequest(req, "udp")
	if err != nil {
		errorsTotal.WithLabelValues("resolve_fail").Inc()
		requestsTotal.WithLabelValues(target, "error").Inc()
		return
	}

	resp.Id = req.Id
	respBytes, _ := resp.Pack()

	conn.SetWriteDeadline(time.Now().Add(forwardTimeout))
	conn.WriteToUDP(respBytes, client)

	cacheLabel := "backend"
	if isHit { cacheLabel = "cache-udp" }
	
	requestsTotal.WithLabelValues(target, "success").Inc()
	responseDuration.WithLabelValues(cacheLabel).Observe(time.Since(start).Seconds())
}


func forwardToBackendUDP(target string, req *dns.Msg) (*dns.Msg, error) {
	backendAddr, _ := net.ResolveUDPAddr("udp", target)
	conn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		errorsTotal.WithLabelValues("dial_fail").Inc()
		return nil, err
	}
	defer conn.Close()

	reqBytes, _ := req.Pack()
	conn.SetWriteDeadline(time.Now().Add(forwardTimeout))
	if _, err := conn.Write(reqBytes); err != nil {
		errorsTotal.WithLabelValues("write_fail").Inc()
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(forwardTimeout))
	respBytes := make([]byte, 4096)
	n, err := conn.Read(respBytes)
	if err != nil {
		errorsTotal.WithLabelValues("read_fail").Inc()
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBytes[:n]); err != nil {
		errorsTotal.WithLabelValues("unpack_fail").Inc()
		return nil, err
	}
	return resp, nil
}

func forwardToBackendTCP(target string, req *dns.Msg) (*dns.Msg, error) {
	conn, err := net.DialTimeout("tcp", target, forwardTimeout)
	if err != nil {
		errorsTotal.WithLabelValues("dial_fail").Inc()
		return nil, err
	}
	defer conn.Close()

	reqBytes, _ := req.Pack()
	conn.SetWriteDeadline(time.Now().Add(forwardTimeout))
	if err := binary.Write(conn, binary.BigEndian, uint16(len(reqBytes))); err != nil {
		errorsTotal.WithLabelValues("write_fail").Inc()
		return nil, err
	}
	if _, err := conn.Write(reqBytes); err != nil {
		errorsTotal.WithLabelValues("write_fail").Inc()
		return nil, err
	}

	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		errorsTotal.WithLabelValues("read_fail").Inc()
		return nil, err
	}

	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
		errorsTotal.WithLabelValues("read_fail").Inc() // 🚀 RESTAURÉ
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBytes); err != nil {
		errorsTotal.WithLabelValues("unpack_fail").Inc() // 🚀 RESTAURÉ
		return nil, err
	}
	return resp, nil
}


// resolveRequest gère la logique métier : Cache -> Backend -> Mise à jour Cache
func resolveRequest(req *dns.Msg, clientProto string) (resp *dns.Msg, target string, isHit bool, err error) {
	cacheKey := getCacheKey(req)

	// 1. Vérification du Cache
	if (enablePositiveCache || enableNegativeCache) && cacheKey != "" {
		cacheMu.RLock()
		var cachedResp *dns.Msg
		var hit bool

		if enablePositiveCache {
			if entry, exists := positiveCache[cacheKey]; exists && isCacheValid(entry) {
				cachedResp = entry.Response.Copy()
				hit = true
				cacheHits.WithLabelValues("positive").Inc()
			}
		}
		if !hit && enableNegativeCache {
			if entry, exists := negativeCache[cacheKey]; exists && isCacheValid(entry) {
				cachedResp = entry.Response.Copy()
				hit = true
				cacheHits.WithLabelValues("negative").Inc()
			}
		}
		cacheMu.RUnlock()

		if hit {
			return cachedResp, "cache", true, nil
		}
	}

	cacheMisses.Inc()

	// 2. Cache Miss : Résolution du backend
	target = getHealthyBackend()
	if target == "" {
		return nil, "none", false, fmt.Errorf("no healthy backend")
	}

	// 3. Forward vers le backend (en utilisant le même protocole que le client)
	var backendErr error
	if clientProto == "tcp" {
		resp, backendErr = forwardToBackendTCP(target, req)
	} else {
		resp, backendErr = forwardToBackendUDP(target, req)
	}

	if backendErr != nil {
		setHealthy(target, false)
		return nil, target, false, backendErr
	}

	if resp != nil {
		// if response is empty, update counter
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			emptyAnswersTotal.WithLabelValues(target).Inc()
		}
	}

	// 4. Mise à jour du Cache avec la réponse fraîche
	if cacheKey != "" {
		cacheMu.Lock()
		if enablePositiveCache && resp.Rcode == dns.RcodeSuccess {
			positiveCache[cacheKey] = &CacheEntry{
				Response:  resp.Copy(),
				ExpiresAt: time.Now().Add(positiveCacheTTL),
			}
			cacheSize.WithLabelValues("positive").Set(float64(len(positiveCache)))
		}
		if enableNegativeCache && resp.Rcode != dns.RcodeSuccess {
			negativeCache[cacheKey] = &CacheEntry{
				Response:  resp.Copy(),
				ExpiresAt: time.Now().Add(negativeCacheTTL),
			}
			cacheSize.WithLabelValues("negative").Set(float64(len(negativeCache)))
		}
		cacheMu.Unlock()
	}

	return resp, target, false, nil
}

/* @obosolete */
// decodeDNSQuery extracts domain name and query type from DNS packet
func decodeDNSQuery(data []byte) (string, string, error) {
	if len(data) < 12 {
		return "", "", fmt.Errorf("packet too short")
	}

	// Skip header (12 bytes), start at question section
	offset := 12
	if offset >= len(data) {
		return "", "", fmt.Errorf("no question section")
	}

	// Decode QNAME (domain name)
	var labels []string
	for {
		if offset >= len(data) {
			return "", "", fmt.Errorf("malformed QNAME")
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if offset+1+length > len(data) {
			return "", "", fmt.Errorf("QNAME too long")
		}
		labels = append(labels, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}
	domain := strings.Join(labels, ".")

	// Decode QTYPE (2 bytes)
	if offset+2 > len(data) {
		return "", "", fmt.Errorf("no QTYPE")
	}
	qtype := uint16(data[offset])<<8 | uint16(data[offset+1])
	
	qtypeStr := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
		15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
	}[qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qtype)
	}

	return domain, qtypeStr, nil
}


// new code:
func runUDPServer(addr string, ctx context.Context) {
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil { log.Fatalf("UDP listen failed: %v", err) }
	defer conn.Close()

	for {
		//buf := make([]byte, 4096)
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(bufPtr)
			if ctx.Err() != nil { return }
			continue
		}

		// copy what we need
		//log.Printf("buffer size is %d bytes", n)
		reqBuf := make([]byte, n)
		copy(reqBuf, buf[:n])

		// free main buffer
		bufferPool.Put(bufPtr)
		
		go forwardRequest(conn, reqBuf, n, client)
	}
}

func runTCPServer(addr string, ctx context.Context) {
	listener, err := net.Listen("tcp", addr)
	if err != nil { log.Fatalf("TCP listen failed: %v", err) }
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil { return }
			continue
		}
		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn net.Conn) {
	defer conn.Close()
	start := time.Now()

	clientIP := "unknown"
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP.String()
	}
	incrementClientStat(clientIP)

	for {
		var msgLen uint16
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			return
		}
		if msgLen > 65535 { return }

		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(payload); err != nil {
			continue
		}

		// 🚀 DEBUG RESTAURÉ pour TCP
		if debugMode && len(req.Question) > 0 {
			q := req.Question[0]
			qtype := dns.TypeToString[q.Qtype]
			if qtype == "" { qtype = fmt.Sprintf("TYPE%d", q.Qtype) }
			log.Printf("[DEBUG] TCP Query from %s: %s %s", conn.RemoteAddr().String(), q.Name, qtype)
		}

		resp, target, isHit, err := resolveRequest(req, "tcp")
		if err != nil {
			continue 
		}

		resp.Id = req.Id
		respBytes, _ := resp.Pack()

		binary.Write(conn, binary.BigEndian, uint16(len(respBytes)))
		conn.Write(respBytes)

		cacheLabel := "backend"
		if isHit { cacheLabel = "cache-tcp" }
		
		requestsTotal.WithLabelValues(target, "success").Inc()
		responseDuration.WithLabelValues(cacheLabel).Observe(time.Since(start).Seconds())
	}
}

/* @obosolete */
func forwardDNSFrames(src, dst net.Conn, isClientSide bool) error {
	for {
		// ⏱️ Timeout lecture (empêche un client de garder la socket ouverte sans rien envoyer)
		src.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		var msgLen uint16
		if err := binary.Read(src, binary.BigEndian, &msgLen); err != nil {
			return err // Timeout, fermeture ou erreur réseau
		}
		if msgLen > 65535 {
			return fmt.Errorf("invalid DNS message length: %d", msgLen)
		}

		// ⏱️ Timeout lecture payload
		src.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(src, payload); err != nil {
			return err
		}

		// Debug uniquement côté client
		if isClientSide && debugMode {
			if domain, qtype, err := decodeDNSQuery(payload); err == nil {
				log.Printf("[DEBUG] TCP Query from %s: %s %s", src.RemoteAddr(), domain, qtype)
			}
		}

		// ⏱️ Timeout écriture (empêche un client lent de bloquer le proxy)
		dst.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
		if err := binary.Write(dst, binary.BigEndian, msgLen); err != nil {
			return err
		}
		dst.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := dst.Write(payload); err != nil {
			return err
		}
	}
}

// loadClientStats charge les données existantes au démarrage
func loadClientStats() {
	data, err := os.ReadFile(statsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("ℹ️ No client stats file found, starting fresh.")
			return
		}
		log.Printf("⚠️ Error reading client stats file: %v", err)
		return
	}

	// 🚀 FIX : Gérer le fichier vide (créé par systemd/touch)
	if len(bytes.TrimSpace(data)) == 0 {
		log.Println("ℹ️ Client stats file is empty, starting fresh.")
		return
	}

	var loaded map[string]int64
	if err := json.Unmarshal(data, &loaded); err != nil {
		// Si le fichier est corrompu, on logue mais on ne crash pas, on repart à zéro
		log.Printf("⚠️ Error parsing client stats JSON (file may be corrupted): %v. Starting fresh.", err)
		return
	}

	clientStatsMu.Lock()
	for ip, count := range loaded {
		counter := &atomic.Int64{}
		counter.Store(count)
		clientStats[ip] = counter
	}
	clientStatsMu.Unlock()
	
	log.Printf("✅ Successfully loaded %d client IP statistics from disk", len(loaded))
}

// incrementClientStat incrémente le compteur de façon thread-safe et ultra-rapide
func incrementClientStat(ip string) {
	clientStatsMu.RLock()
	counter, exists := clientStats[ip]
	clientStatsMu.RUnlock()

	if exists {
		counter.Add(1) // Chemin rapide (99.9% des cas)
	} else {
		// Chemin lent (nouvelle IP) : double-checked locking
		clientStatsMu.Lock()
		if counter, exists = clientStats[ip]; !exists {
			counter = &atomic.Int64{}
			clientStats[ip] = counter
		}
		clientStatsMu.Unlock()
		counter.Add(1)
	}
}

// dumpClientStats sauvegarde l'état actuel sur disque de manière atomique
func dumpClientStats() {
	clientStatsMu.RLock()
	// Créer un snapshot pour ne pas bloquer les incréments pendant l'écriture disque
	snapshot := make(map[string]int64, len(clientStats))
	for ip, counter := range clientStats {
		snapshot[ip] = counter.Load()
	}
	clientStatsMu.RUnlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		log.Printf("❌ Error marshaling client stats: %v", err)
		return
	}

	// Écriture atomique : on écrit dans un fichier .tmp, puis on renomme
	tmpFile := statsFilePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		log.Printf("❌ Error writing temp client stats: %v", err)
		return
	}
	if err := os.Rename(tmpFile, statsFilePath); err != nil {
		log.Printf("❌ Error renaming client stats file: %v", err)
		return
	}
	log.Printf("📥 Dumped %d client IP statistics to %s", len(snapshot), statsFilePath)
}

func initDnsProbe(domain string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA) 
	msg.RecursionDesired = true
	
	var err error
	dnsProbe, err = msg.Pack()
	if err != nil {
		log.Fatalf("❌ Impossible to generate DNS probe for domain '%s': %v", domain, err)
	}	
	log.Printf("✅ DNS Probe initialized for domain: %s (%d bytes)", dns.Fqdn(domain), len(dnsProbe))
}

func main() {
	var port int
	var logFile string
	flag.IntVar(&port, "port", 53, "UDP port to listen on")
	flag.IntVar(&metricsPort, "metricsPort", 9100, "Prometheus port to listen on")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode to print DNS queries") 
	flag.StringVar(&logFile, "log", "", "Path to log file (default: stdout)")
	flag.StringVar(&statsFilePath, "statsFile", statsFilePath, "Path to JSON stats file")

	flag.BoolVar(&enablePositiveCache, "cache-positive", false, "Enable positive DNS cache")
	flag.BoolVar(&enableNegativeCache, "cache-negative", false, "Enable negative DNS cache (errors)")
	flag.DurationVar(&positiveCacheTTL, "cache-positive-ttl", 1*time.Hour, "TTL for positive cache (e.g., 1h, 30m, 60s)")
	flag.DurationVar(&negativeCacheTTL, "cache-negative-ttl", 60*time.Second, "TTL for negative cache (e.g., 1h, 30m, 60s)")

	flag.StringVar(&zombieCheckDomain, "zombie-check-domain", "", "Domain to use for zombie check. If a response asking for this record is empty, then backend is marked as unhealthy")
	
	flag.Parse()


	// 📝 Dual logging : terminal/journald + fichier
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			// N'empêche pas le daemon de démarrer
			log.Printf("WARNING: Cannot open log file %s: %v (falling back to stdout only)", logFile, err)
		} else {
			// log.SetOutput remplace la sortie par défaut (stderr). 
			// MultiWriter assure l'écriture atomique sur les 2 destinations.
			log.SetOutput(io.MultiWriter(os.Stderr, f))
			defer f.Close()
		}
	}
	
	if port < 1 || port > 65535 {
		log.Fatalf("Invalid port: %d (must be 1-65535)", port)
	}

	backendStr := "1.2.3.4:53,5.6.7.8:53"
	if env := os.Getenv("DNS_BACKENDS"); env != "" {
		backendStr = env
	}
	backends = strings.Split(backendStr, ",")
	for i, b := range backends {
		backends[i] = strings.TrimSpace(b)
		if backends[i] == "" {
			log.Fatalf("Empty backend in list: %s", backendStr)
		}
		if !strings.Contains(backends[i], ":") {
			backends[i] += ":53"
		}
		setHealthy(backends[i], true)
	}

	if zombieCheckDomain != "" {
		initDnsProbe(zombieCheckDomain)
	} else {
		initDnsProbe("example.com")
	}	

	listenAddr := fmt.Sprintf(":%d", port)
	log.Printf("Starting DNS UDP LB on %s, backends: %v", listenAddr, backends)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load stats
	loadClientStats()
	
	// 🚀 Prometheus metrics server
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("Prometheus metrics listening on :%d/metrics", metricsPort)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", metricsPort), mux); err != nil && err != http.ErrServerClosed {
			log.Printf("Metrics server failed: %v", err)
		}
	}()

	// 🚀 Nettoyer les caches expirés toutes les minutes
	if enablePositiveCache || enableNegativeCache {
		log.Printf("Activating cache with following TTLs: %s / %s (positive/negative)", positiveCacheTTL, negativeCacheTTL)
		go cleanExpiredCache()
		go displayStats()
	}
	
	// 🩺 Healthcheck loop
	go healthcheck(ctx)

	// 🌐 Protocol switch
	log.Printf("Starting DNS LB on %s, backends: %v", listenAddr, backends)

	// 🌐 Écoute simultanée TCP + UDP sur le même port
	go runUDPServer(listenAddr, ctx)
	go runTCPServer(listenAddr, ctx)

	// 🚀 GESTION UNIFIÉE DES SIGNAUX
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	log.Println("🚀 DNS Load Balancer started and ready")

	// Boucle principale : attend les signaux
	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGUSR1:
			// 📥 Dump à la demande (ne quitte pas)
			log.Println("📥 Received SIGUSR1, triggering client stats dump...")
			dumpClientStats()

		case syscall.SIGINT, syscall.SIGTERM:
			// 🛑 Arrêt gracieux
			log.Printf("🛑 Received %s, initiating graceful shutdown...", sig)

			// 1. Annuler le contexte → arrête les listeners UDP/TCP et healthcheck
			cancel()

			// 2. Petit délai pour laisser les requêtes en cours se terminer
			time.Sleep(1 * time.Second)

			// 3. Sauvegarder les stats AVANT de quitter
			log.Println("💾 Saving final client statistics to disk...")
			dumpClientStats()

			log.Println("✅ Shutdown complete. Exiting.")
			os.Exit(0)
		}
	}

}
