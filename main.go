package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSmallBytes = 10 * 1024
	defaultLargeBytes = 8 * 1024 * 1024
	defaultWorkers    = 256
	defaultTimeout    = 8 * time.Second
	defaultTop        = 20
)

var cloudflareIPv4CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

type config struct {
	rawTrojan          string
	inputs             string
	inputFile          string
	fullCloudflare     bool
	workers            int
	samplePerCIDR      int
	sampleSeed         uint64
	maxCandidates      int
	timeout            time.Duration
	top                int
	probeHost          string
	probePort          int
	probePath          string
	smallBytes         int64
	largeBytes         int64
	throughputDuration time.Duration
	insecure           bool
	verbose            bool
}

type trojanConfig struct {
	Password string
	Server   string
	Port     string
	SNI      string
	ALPN     []string
	Host     string
	Path     string
}

type result struct {
	IP              netip.Addr
	TCP             time.Duration
	OuterTLS        time.Duration
	WS              time.Duration
	ProxyConnect    time.Duration
	TTFB            time.Duration
	SmallDownload   time.Duration
	BytesDownloaded int64
	ThroughputMbps  float64
	Score           float64
	Error           string
}

type timedConn struct {
	net.Conn
	reader *bufio.Reader
}

func main() {
	cfg := parseFlags()
	if cfg.rawTrojan == "" {
		fail("missing required --url trojan://...")
	}

	tc, err := parseTrojanURL(cfg.rawTrojan)
	if err != nil {
		fail("invalid trojan url: %v", err)
	}
	if cfg.probeHost == "" {
		cfg.probeHost = "speed.cloudflare.com"
	}
	if cfg.probePath == "" {
		cfg.probePath = "/__down?bytes=" + strconv.FormatInt(cfg.smallBytes+cfg.largeBytes, 10)
	}

	candidates, err := buildCandidates(cfg)
	if err != nil {
		fail("%v", err)
	}
	if len(candidates) == 0 {
		fail("no candidate IPv4 addresses")
	}

	fmt.Fprintf(os.Stderr, "trojan target: %s:%s sni=%s ws_host=%s path=%s\n", tc.Server, tc.Port, tc.SNI, tc.Host, tc.Path)
	fmt.Fprintf(os.Stderr, "probe target: https://%s:%d%s\n", cfg.probeHost, cfg.probePort, cfg.probePath)
	fmt.Fprintf(os.Stderr, "candidates=%d workers=%d timeout=%s\n\n", len(candidates), cfg.workers, cfg.timeout)
	printHeader()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan netip.Addr)
	results := make(chan result)
	var tested atomic.Uint64
	var wg sync.WaitGroup

	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				res := probeCandidate(ctx, cfg, tc, ip)
				tested.Add(1)
				if res.Error == "" {
					results <- res
				} else if cfg.verbose {
					fmt.Fprintf(os.Stderr, "%s failed: %s\n", ip, res.Error)
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	best := make([]result, 0, cfg.top)
	for res := range results {
		insertBest(&best, res, cfg.top)
		printResult(res)
	}

	fmt.Fprintf(os.Stderr, "\nscanned=%d working=%d\n", tested.Load(), len(best))
	if len(best) > 0 {
		fmt.Fprintln(os.Stderr, "\ntop results:")
		printHeader()
		for _, res := range best {
			printResult(res)
		}
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.rawTrojan, "url", "", "trojan:// URL to scan for")
	flag.StringVar(&cfg.inputs, "ips", "", "comma-separated IPv4 addresses or CIDRs to scan")
	flag.StringVar(&cfg.inputFile, "ip-file", "", "file containing IPv4 addresses or CIDRs, one per line")
	flag.BoolVar(&cfg.fullCloudflare, "full-cloudflare", false, "scan embedded Cloudflare IPv4 ranges")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "concurrent scan workers")
	flag.IntVar(&cfg.samplePerCIDR, "sample-per-cidr", 0, "sample N deterministic addresses from each /24 inside each CIDR instead of expanding every address")
	flag.Uint64Var(&cfg.sampleSeed, "sample-seed", 0, "seed for deterministic address sampling within each /24")
	flag.IntVar(&cfg.maxCandidates, "max-candidates", 0, "stop after N candidate addresses have been generated")
	flag.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "per-candidate timeout")
	flag.IntVar(&cfg.top, "top", defaultTop, "number of top results to print again at the end")
	flag.StringVar(&cfg.probeHost, "probe-host", "speed.cloudflare.com", "HTTPS host to fetch through the Trojan tunnel")
	flag.IntVar(&cfg.probePort, "probe-port", 443, "probe HTTPS port")
	flag.StringVar(&cfg.probePath, "probe-path", "", "probe HTTPS path; default asks speed.cloudflare.com for small+large bytes")
	flag.Int64Var(&cfg.smallBytes, "small-bytes", defaultSmallBytes, "bytes used for low-latency small download timing")
	flag.Int64Var(&cfg.largeBytes, "large-bytes", defaultLargeBytes, "bytes used for throughput timing after the small download")
	flag.DurationVar(&cfg.throughputDuration, "throughput-duration", 4*time.Second, "maximum time spent reading throughput bytes")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip TLS certificate verification for the outer Trojan TLS connection")
	flag.BoolVar(&cfg.verbose, "verbose", false, "print failed candidate errors to stderr")
	flag.Parse()

	if cfg.probePort <= 0 || cfg.probePort > 65535 {
		fail("--probe-port must be between 1 and 65535")
	}
	if cfg.workers <= 0 {
		fail("--workers must be positive")
	}
	if cfg.samplePerCIDR < 0 {
		fail("--sample-per-cidr cannot be negative")
	}
	if cfg.top <= 0 {
		fail("--top must be positive")
	}
	if cfg.smallBytes <= 0 {
		fail("--small-bytes must be positive")
	}
	if cfg.largeBytes < 0 {
		fail("--large-bytes cannot be negative")
	}
	return cfg
}

func parseTrojanURL(raw string) (trojanConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return trojanConfig{}, err
	}
	if u.Scheme != "trojan" {
		return trojanConfig{}, fmt.Errorf("expected trojan scheme, got %q", u.Scheme)
	}
	password, ok := u.User.Password()
	if !ok {
		password = u.User.Username()
	}
	if password == "" {
		return trojanConfig{}, errors.New("missing password")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	q := u.Query()
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), u.Hostname())
	host := firstNonEmpty(q.Get("host"), sni)
	path := q.Get("path")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	alpn := []string{"http/1.1"}
	if rawALPN := q.Get("alpn"); rawALPN != "" {
		alpn = splitList(rawALPN)
	}

	return trojanConfig{
		Password: password,
		Server:   u.Hostname(),
		Port:     port,
		SNI:      sni,
		ALPN:     alpn,
		Host:     host,
		Path:     path,
	}, nil
}

func buildCandidates(cfg config) ([]netip.Addr, error) {
	tokens := make([]string, 0)
	if cfg.fullCloudflare {
		tokens = append(tokens, cloudflareIPv4CIDRs...)
	}
	if cfg.inputs != "" {
		tokens = append(tokens, splitList(cfg.inputs)...)
	}
	if cfg.inputFile != "" {
		fileTokens, err := readInputFile(cfg.inputFile)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, fileTokens...)
	}
	if len(tokens) == 0 {
		return nil, errors.New("provide --ips, --ip-file, or --full-cloudflare")
	}

	seen := make(map[netip.Addr]struct{})
	candidates := make([]netip.Addr, 0)
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" || strings.HasPrefix(token, "#") {
			continue
		}
		var expanded []netip.Addr
		if strings.Contains(token, "/") {
			prefix, err := netip.ParsePrefix(token)
			if err != nil {
				return nil, fmt.Errorf("parse CIDR %q: %w", token, err)
			}
			if !prefix.Addr().Is4() {
				continue
			}
			expanded = expandPrefix(prefix.Masked(), cfg.samplePerCIDR, cfg.sampleSeed)
		} else {
			addr, err := netip.ParseAddr(token)
			if err != nil {
				return nil, fmt.Errorf("parse IP %q: %w", token, err)
			}
			if !addr.Is4() {
				continue
			}
			expanded = []netip.Addr{addr}
		}
		for _, addr := range expanded {
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			candidates = append(candidates, addr)
			if cfg.maxCandidates > 0 && len(candidates) >= cfg.maxCandidates {
				return candidates, nil
			}
		}
	}
	return candidates, nil
}

func readInputFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tokens []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			tokens = append(tokens, line)
		}
	}
	return tokens, scanner.Err()
}

func expandPrefix(prefix netip.Prefix, sample int, seed uint64) []netip.Addr {
	ones := prefix.Bits()
	totalBits := prefix.Addr().BitLen()
	sizeBits := totalBits - ones
	if sizeBits <= 0 {
		return []netip.Addr{prefix.Addr()}
	}
	if sample > 0 {
		return samplePrefixPer24(prefix, sample, seed)
	}
	if sizeBits >= 31 {
		return samplePrefix(prefix, 4096, seed)
	}
	size := uint64(1) << uint(sizeBits)
	out := make([]netip.Addr, 0, size)
	base := ipv4ToUint32(prefix.Addr())
	for i := uint64(0); i < size; i++ {
		out = append(out, uint32ToIPv4(base+uint32(i)))
	}
	return out
}

func samplePrefixPer24(prefix netip.Prefix, n int, seed uint64) []netip.Addr {
	if prefix.Bits() >= 24 {
		return samplePrefix(prefix, n, seed)
	}

	base := ipv4ToUint32(prefix.Addr())
	size := uint64(1) << uint(32-prefix.Bits())
	blocks := size / 256
	out := make([]netip.Addr, 0, blocks*uint64(minInt(n, 256)))
	for block := uint64(0); block < blocks; block++ {
		blockPrefix := netip.PrefixFrom(uint32ToIPv4(base+uint32(block*256)), 24)
		out = append(out, samplePrefix(blockPrefix, n, seed)...)
	}
	return out
}

func samplePrefix(prefix netip.Prefix, n int, seed uint64) []netip.Addr {
	if n <= 0 {
		n = 1
	}
	ones := prefix.Bits()
	size := uint64(1) << uint(32-ones)
	if uint64(n) > size {
		n = int(size)
	}
	base := ipv4ToUint32(prefix.Addr())
	out := make([]netip.Addr, 0, n)

	if size <= 65536 {
		ranks := make([]sampledOffset, 0, size)
		for offset := uint64(0); offset < size; offset++ {
			ranks = append(ranks, sampledOffset{
				offset: offset,
				rank:   sampleRank(seed, base, offset),
			})
		}
		sort.Slice(ranks, func(i, j int) bool {
			if ranks[i].rank == ranks[j].rank {
				return ranks[i].offset < ranks[j].offset
			}
			return ranks[i].rank < ranks[j].rank
		})
		for i := 0; i < n; i++ {
			out = append(out, uint32ToIPv4(base+uint32(ranks[i].offset)))
		}
		return out
	}

	seen := make(map[uint32]struct{}, n)
	var x uint64 = sampleRank(seed, base, 0)
	for len(out) < n {
		x += 0x9e3779b97f4a7c15
		ip := base + uint32(mix64(x)%size)
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, uint32ToIPv4(ip))
	}
	return out
}

type sampledOffset struct {
	offset uint64
	rank   uint64
}

func sampleRank(seed uint64, base uint32, offset uint64) uint64 {
	return mix64(seed ^ uint64(base) ^ (offset * 0x9e3779b97f4a7c15))
}

func mix64(x uint64) uint64 {
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func probeCandidate(ctx context.Context, cfg config, tc trojanConfig, ip netip.Addr) result {
	res := result{IP: ip}
	candidateCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	conn, tcpDur, err := dialTCP(candidateCtx, ip, tc.Port)
	if err != nil {
		res.Error = "tcp: " + err.Error()
		return res
	}
	defer conn.Close()
	res.TCP = tcpDur

	tlsConn, tlsDur, err := handshakeOuterTLS(candidateCtx, conn, tc, cfg.insecure)
	if err != nil {
		res.Error = "tls: " + err.Error()
		return res
	}
	res.OuterTLS = tlsDur

	wsConn, wsDur, err := websocketUpgrade(candidateCtx, tlsConn, tc)
	if err != nil {
		res.Error = "websocket: " + err.Error()
		return res
	}
	res.WS = wsDur

	startProxy := time.Now()
	if err := writeTrojanConnect(wsConn, tc.Password, cfg.probeHost, cfg.probePort); err != nil {
		res.Error = "trojan connect: " + err.Error()
		return res
	}
	res.ProxyConnect = time.Since(startProxy)

	innerTLS, err := handshakeInnerTLS(candidateCtx, wsConn, cfg.probeHost)
	if err != nil {
		res.Error = "inner tls: " + err.Error()
		return res
	}

	ttfb, smallDur, bytesRead, throughput, err := fetchProbe(candidateCtx, innerTLS, cfg)
	if err != nil {
		res.Error = "probe fetch: " + err.Error()
		return res
	}
	res.TTFB = ttfb
	res.SmallDownload = smallDur
	res.BytesDownloaded = bytesRead
	res.ThroughputMbps = throughput
	res.Score = scoreResult(res)
	return res
}

func dialTCP(ctx context.Context, ip netip.Addr, port string) (net.Conn, time.Duration, error) {
	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
	return conn, time.Since(start), err
}

func handshakeOuterTLS(ctx context.Context, conn net.Conn, tc trojanConfig, insecure bool) (*tls.Conn, time.Duration, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         tc.SNI,
		NextProtos:         tc.ALPN,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	})
	start := time.Now()
	err := tlsConn.HandshakeContext(ctx)
	return tlsConn, time.Since(start), err
}

func websocketUpgrade(ctx context.Context, conn net.Conn, tc trojanConfig) (*wsConn, time.Duration, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, 0, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := tc.Path
	if path == "" {
		path = "/"
	}

	req := strings.Builder{}
	req.WriteString("GET " + path + " HTTP/1.1\r\n")
	req.WriteString("Host: " + tc.Host + "\r\n")
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	req.WriteString("User-Agent: trojan-scanner/0.1\r\n")
	req.WriteString("\r\n")

	start := time.Now()
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return nil, 0, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, 0, fmt.Errorf("unexpected status %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, 0, errors.New("missing websocket upgrade header")
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), websocketAccept(key); got != want {
		return nil, 0, fmt.Errorf("invalid websocket accept key")
	}
	return &wsConn{conn: &timedConn{Conn: conn, reader: br}}, time.Since(start), nil
}

func writeTrojanConnect(w io.Writer, password, host string, port int) error {
	hash := sha224Hex(password)
	var payload bytes.Buffer
	payload.WriteString(hash)
	payload.WriteString("\r\n")
	payload.WriteByte(0x01)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			payload.WriteByte(0x01)
			payload.Write(ip4)
		} else {
			ip16 := ip.To16()
			if ip16 == nil {
				return fmt.Errorf("invalid ip %q", host)
			}
			payload.WriteByte(0x04)
			payload.Write(ip16)
		}
	} else {
		if len(host) > 255 {
			return errors.New("host name too long")
		}
		payload.WriteByte(0x03)
		payload.WriteByte(byte(len(host)))
		payload.WriteString(host)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	payload.Write(p[:])
	payload.WriteString("\r\n")
	_, err := w.Write(payload.Bytes())
	return err
}

func handshakeInnerTLS(ctx context.Context, conn net.Conn, host string) (*tls.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		NextProtos: []string{
			"http/1.1",
		},
		MinVersion: tls.VersionTLS12,
	})
	return tlsConn, tlsConn.HandshakeContext(ctx)
}

func fetchProbe(ctx context.Context, conn net.Conn, cfg config) (time.Duration, time.Duration, int64, float64, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	reqPath := cfg.probePath
	if reqPath == "" {
		reqPath = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: trojan-scanner/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n", reqPath, cfg.probeHost)
	start := time.Now()
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, 0, 0, 0, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, 0, 0, 0, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	ttfb := time.Since(start)

	buf := make([]byte, 32*1024)
	var total int64
	smallStart := time.Now()
	var smallDur time.Duration
	throughputStart := time.Time{}
	var throughputBytes int64

	for total < cfg.smallBytes+cfg.largeBytes {
		if !throughputStart.IsZero() && cfg.throughputDuration > 0 && time.Since(throughputStart) >= cfg.throughputDuration {
			break
		}
		remaining := cfg.smallBytes + cfg.largeBytes - total
		readSize := len(buf)
		if remaining < int64(readSize) {
			readSize = int(remaining)
		}
		n, err := resp.Body.Read(buf[:readSize])
		if n > 0 {
			total += int64(n)
			if total >= cfg.smallBytes && smallDur == 0 {
				smallDur = time.Since(smallStart)
				throughputStart = time.Now()
			} else if smallDur != 0 {
				throughputBytes += int64(n)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return ttfb, smallDur, total, 0, err
		}
	}
	if smallDur == 0 {
		return ttfb, 0, total, 0, fmt.Errorf("only downloaded %d bytes before small-byte threshold %d", total, cfg.smallBytes)
	}
	throughputSeconds := time.Since(throughputStart).Seconds()
	var mbps float64
	if throughputSeconds > 0 && throughputBytes > 0 {
		mbps = float64(throughputBytes*8) / throughputSeconds / 1_000_000
	}
	return ttfb, smallDur, total, mbps, nil
}

func sha224Hex(s string) string {
	// crypto/sha256 exposes SHA-224 in the standard library.
	sum := sha256.Sum224([]byte(s))
	return hex.EncodeToString(sum[:])
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type wsConn struct {
	conn *timedConn
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (c *wsConn) Read(p []byte) (int, error) {
	for c.buf.Len() == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
	return c.buf.Read(p)
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 16*1024 {
			chunk = chunk[:16*1024]
		}
		if err := c.writeFrame(0x2, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *wsConn) Close() error {
	_ = c.writeFrame(0x8, nil)
	return c.conn.Close()
}

func (c *wsConn) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr              { return c.conn.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *wsConn) readFrame() error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.conn.reader, header); err != nil {
		return err
	}
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.conn.reader, ext[:]); err != nil {
			return err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.conn.reader, ext[:]); err != nil {
			return err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.conn.reader, mask[:]); err != nil {
			return err
		}
	}
	if length > 64*1024*1024 {
		return fmt.Errorf("websocket frame too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn.reader, payload); err != nil {
		return err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	switch opcode {
	case 0x0, 0x2:
		c.buf.Write(payload)
		return nil
	case 0x8:
		return io.EOF
	case 0x9:
		return c.writeFrame(0xA, payload)
	case 0xA:
		return nil
	default:
		return fmt.Errorf("unsupported websocket opcode %d", opcode)
	}
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode)
	maskBit := byte(0x80)
	switch {
	case len(payload) < 126:
		header = append(header, maskBit|byte(len(payload)))
	case len(payload) <= math.MaxUint16:
		header = append(header, maskBit|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		header = append(header, ext[:]...)
	default:
		header = append(header, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		header = append(header, ext[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(masked)
	return err
}

func scoreResult(r result) float64 {
	latencyMS := float64((r.TCP + r.OuterTLS + r.WS + r.TTFB).Milliseconds())
	smallMS := float64(r.SmallDownload.Milliseconds())
	if latencyMS < 1 {
		latencyMS = 1
	}
	if smallMS < 1 {
		smallMS = 1
	}
	throughput := r.ThroughputMbps
	if throughput < 0.1 {
		throughput = 0.1
	}
	return throughput * 1000 / (latencyMS + smallMS)
}

func insertBest(best *[]result, res result, limit int) {
	*best = append(*best, res)
	sort.Slice(*best, func(i, j int) bool {
		return (*best)[i].Score > (*best)[j].Score
	})
	if len(*best) > limit {
		*best = (*best)[:limit]
	}
}

func printHeader() {
	fmt.Printf("%-15s %8s %8s %8s %8s %9s %9s %10s %8s\n",
		"ip", "tcp", "tls", "ws", "ttfb", "10kb", "mbps", "score", "bytes")
}

func printResult(r result) {
	fmt.Printf("%-15s %8s %8s %8s %8s %9s %9.2f %10.2f %8d\n",
		r.IP,
		formatDuration(r.TCP),
		formatDuration(r.OuterTLS),
		formatDuration(r.WS),
		formatDuration(r.TTFB),
		formatDuration(r.SmallDownload),
		r.ThroughputMbps,
		r.Score,
		r.BytesDownloaded,
	)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

func uint32ToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := fields[:0]
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
