# DNS-LB 🚀

**DNS-LB** is a high-performance DNS proxy and load balancer written in Go. Designed for demanding production environments, it combines minimal memory footprint, strict systemd hardening, and native observability via Prometheus.

All packed in a **~8 MB static binary** with zero system dependencies.

---

## ✨ Features

- **Load Balancing**: Round-robin distribution across multiple DNS backends.
- **UDP & TCP Support**: Full support for both protocols, including TCP framing and pipelining (AXFR/IXFR compatible).
- **Intelligent Caching**: 
  - Positive cache (NOERROR) and negative cache (NXDOMAIN, SERVFAIL).
  - Independently configurable TTLs to prevent temporary error propagation.
- **Resilient Healthchecks**: 
  - Failure detection with tolerance (N consecutive failures).
  - Degraded mode (fallback) to prevent total lockouts.
- **Observability**: 
  - Native Prometheus metrics (RPS, P50/P90/P99 latency, backend status, cache hits/misses).
  - Ready-to-use Grafana v12 dashboard.
- **Lightweight Client Tracking**: Per-IP counting via internal hash table with atomic JSON dump (avoids Prometheus cardinality explosion).
- **Security & Sandboxing**: Hardened systemd configuration (`ProtectSystem=strict`, `ReadWritePaths`, `LogsDirectory`).
- **Zero Dependencies**: `CGO_ENABLED=0` compilation, easy deployment on Linux, BSD, or in containers.

---

## 🚀 Quick Start

### 1. Build
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -a -installsuffix cgo -o dns-lb dns-lb.go
```

### 2. Launch
```bash
DNS_BACKENDS=8.8.8.8:53,8.8.4.4:53 ./dns-lb \
  -port 5353 \
  -metricsPort 9100 \
  -cache-positive -cache-positive-ttl 1h \
  -cache-negative -cache-negative-ttl 60s \
  -log /var/log/dns-lb/dns-lb.log \
  -debug
```

### 3. Verify
```bash
# Test resolution
dig @localhost -p5353 example.com +short

# Check metrics
curl -s http://localhost:9100/metrics | grep dns_lb
```

---

## ⚙️ Configuration Options

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `53` | UDP/TCP listen port. |
| `-metricsPort` | `9100` | HTTP port for Prometheus metrics exposure. |
| `-cache-positive` | `false` | Enable cache for successful DNS responses. |
| `-cache-positive-ttl` | `1h` | TTL for positive cache. |
| `-cache-negative` | `false` | Enable cache for DNS errors (NXDOMAIN, etc.). |
| `-cache-negative-ttl` | `60s` | TTL for negative cache. |
| `-debug` | `false` | Enable detailed DNS query logging. |
| `-log` | `stdout` | Path to log file (dual-output with journald). |

---

## 🏗️ Systemd Deployment (Production)

To benefit from strict sandboxing, create the log directory and stats file:

```bash
sudo mkdir -p /var/log/dns-lb
sudo chown dns-lb:dns-lb /var/log/dns-lb
sudo touch /var/log/dns-lb/client-stats.json
sudo chown dns-lb:dns-lb /var/log/dns-lb/client-stats.json
```

Example `dns-lb.service` file:
```ini
[Unit]
Description=DNS Load Balancer Proxy
After=network.target

[Service]
Type=simple
User=dns-lb
Group=dns-lb
EnvironmentFile=-/etc/default/dns-lb
ExecStart=/usr/local/bin/dns-lb -port 53 -log /var/log/dns-lb/dns-lb.log ${EXTRA_ARGS}

# Systemd hardening
ProtectSystem=strict
ReadWritePaths=/var/log/dns-lb
LogsDirectory=dns-lb
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Supported Unix Signals
- `SIGUSR1`: Triggers immediate dump of client statistics to disk (`client-stats.json`).
- `SIGTERM` / `SIGINT`: Graceful shutdown (dump stats before closing).

---

## 📊 Monitoring & Grafana

The proxy exposes a Prometheus endpoint on the configured port (`--metrics-port`). 

A complete Grafana dashboard is available in the `/grafana` folder. It includes:
- Overview panels (Backends UP, RPS, Success Rate).
- Latency graphs (P50/P90/P99).
- Error distribution and cache efficiency.
- Malformed packet rate.

---

## 📈 Benchmarking

A dedicated benchmarking tool (`dns-bench.go`) is included for load testing.

**Typical results (localhost, 1000 workers, 10k requests):**
```text
=== Results ===
  Time taken for tests:    2.289 seconds
  Complete requests:       10000
  Successful requests:     9655
  Failed requests:         345
  Failure rate:            3.45%
  Requests per second:     4369.48 [#/sec] (mean)
  Time per request:        0.229 [ms] (mean)
```
*(The residual failure rate is inherent to UDP's best-effort delivery).*

**Usage:**
```bash
go run ./dns-bench/main.go -protocol udp -timeout 2s -forks 10 -threads 100 -total 10000 localhost example.com
```

---

## 🏛️ Architecture

```
    DNS Client
         │
         ▼
   ┌─────────────────────────────────────┐
   │         DNS-LB Proxy                │
   │                                     │
   │  1. Parse request (miekg/dns)       │
   │  2. Cache lookup (positive/negative)│
   │     ├─ HIT  → Immediate response    │
   │     └─ MISS → Select backend        │
   │  3. Round-robin (thread-safe)       │
   │  4. Forward UDP/TCP to backend      │
   │  5. Update cache + metrics          │
   └─────────────────────────────────────┘
         │                │
         ▼                ▼
   Backend 1          Backend 2
   (BIND/Unbound)    (PowerDNS/CoreDNS)
```

---

