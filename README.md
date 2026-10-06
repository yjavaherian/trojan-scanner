# Trojan Cloudflare Scanner

Fast Linux terminal scanner for finding Cloudflare IPv4 addresses that work with a Trojan-over-WebSocket server.

The scanner verifies real usability for each candidate IP:

1. TCP connect to the candidate IP and Trojan port.
2. TLS handshake using the Trojan URL SNI.
3. WebSocket upgrade using the Trojan URL `host` and `path`.
4. Trojan `CONNECT` through the tunnel.
5. HTTPS download through the tunnel from a probe host.

Working IPs are printed immediately as they are found, then the best results are printed again at the end.

## Build

```bash
go build -o trojan-scanner .
```

## Scan Your Own IPs

```bash
./trojan-scanner \
  --url 'trojan://...' \
  --ips '104.16.0.0/24,172.64.0.1'
```

## Scan Cloudflare Ranges

Full Cloudflare IPv4 scanning is large. Start with sampling, then increase coverage.

```bash
./trojan-scanner \
  --url 'trojan://...' \
  --full-cloudflare \
  --sample-per-cidr 1 \
  --sample-seed 0 \
  --workers 16
```

To scan every embedded Cloudflare IPv4 address, omit `--sample-per-cidr`. This can take a long time.

## Flags

- `--ips`: Comma-separated IPv4 addresses or CIDRs.
- `--ip-file`: File with one IPv4 address or CIDR per line.
- `--full-cloudflare`: Use embedded Cloudflare IPv4 ranges.
- `--sample-per-cidr`: Deterministically sample this many addresses from each `/24` block inside every CIDR instead of expanding it fully.
- `--sample-seed`: Seed for deterministic address sampling within each `/24`. Default: `0`.
- `--workers`: Number of concurrent scanners. Default: `256`.
- `--timeout`: Per-candidate timeout. Default: `8s`.
- `--small-bytes`: Small download size for latency ranking. Default: `10240`.
- `--large-bytes`: Extra bytes for throughput ranking. Default: `8388608`.
- `--throughput-duration`: Maximum time spent measuring throughput after the small download. Default: `4s`.
- `--probe-host`, `--probe-port`, `--probe-path`: HTTPS target fetched through the Trojan tunnel. Default host is `speed.cloudflare.com`.
- `--verbose`: Print failed candidate errors.
