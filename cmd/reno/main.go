package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kiiimatz/reno/pkg/protocol"
)

// ─── Config ──────────────────────────────────────────────────────────────────

type Config struct {
	DashboardURL string        `json:"dashboard_url"`
	APISecret    string        `json:"api_secret"`
	Station      StationConfig `json:"station"`
	Edge         EdgeConfig    `json:"edge"`
}

type StationConfig struct {
	Name        string `json:"name"`
	ControlPort int    `json:"control_port"`
}

type EdgeConfig struct {
	StationID string `json:"station_id"`
}

func configPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "reno", "config.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "reno", "config.json")
}

func loadConfig() Config {
	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config not found. Run 'reno config' to set up.\n")
		os.Exit(1)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "station":
		runStation()
	case "edge":
		runEdge()
	case "config":
		runConfig()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  reno station   Start the Station server")
	fmt.Println("  reno edge      Start the Edge client")
	fmt.Println("  reno config    Edit configuration")
}

// ─── Config command ───────────────────────────────────────────────────────────

func runConfig() {
	path := configPath()
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("create config dir: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		def := Config{
			DashboardURL: "https://reno-dashboard.hideko332200.workers.dev",
			APISecret:    "",
			Station: StationConfig{
				Name:        "my-station",
				ControlPort: 7000,
			},
			Edge: EdgeConfig{
				StationID: "",
			},
		}
		data, _ := json.MarshalIndent(def, "", "  ")
		if err := os.WriteFile(path, data, 0600); err != nil {
			log.Fatalf("write config: %v", err)
		}
		fmt.Printf("Created default config: %s\n", path)
	} else {
		fmt.Printf("Config: %s\n", path)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		if runtime.GOOS == "windows" {
			editor = "notepad"
		} else {
			for _, e := range []string{"nano", "vim", "vi"} {
				if _, err := exec.LookPath(e); err == nil {
					editor = e
					break
				}
			}
		}
	}
	if editor == "" {
		fmt.Printf("Edit the file manually: %s\n", path)
		return
	}
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// ─── Crypto ───────────────────────────────────────────────────────────────────

func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func cryptoDecrypt(secret, encoded string) (string, error) {
	key := deriveKey(secret)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("ciphertext too short")
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ─── Station globals ──────────────────────────────────────────────────────────

var (
	stationID string
	certPEM   []byte
	keyPEM    []byte
	certFP    string

	edgesMu sync.RWMutex
	edges   = make(map[string]*edgeConn)

	// TCP channels: channelID → conn to external client
	tcpChannelsMu sync.RWMutex
	tcpChannels   = make(map[uint32]*tcpChannel)

	// UDP return channels: channelID → where to send response packets back
	udpReturnMu sync.RWMutex
	udpReturns  = make(map[uint32]*udpReturn)

	channelCounter uint32

	tunnelsMu sync.RWMutex
	tunnels   []protocol.TunnelConfig

	// TCP listeners
	tcpListenersMu sync.Mutex
	tcpListeners   = make(map[string]net.Listener)

	// UDP listeners
	udpListenersMu sync.Mutex
	udpListeners   = make(map[string]net.PacketConn)
)

type edgeConn struct {
	id     string
	writer *protocol.Writer
}

type tcpChannel struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

// udpReturn tracks where to send UDP response packets on Station side.
type udpReturn struct {
	pc       net.PacketConn
	srcAddr  net.Addr
	lastSeen time.Time
}

// ─── Station ──────────────────────────────────────────────────────────────────

func runStation() {
	cfg := loadConfig()
	if cfg.Station.Name == "" {
		log.Fatal("station.name is not set in config")
	}
	if cfg.APISecret == "" {
		log.Fatal("api_secret is not set in config")
	}
	if cfg.DashboardURL == "" {
		log.Fatal("dashboard_url is not set in config")
	}
	if cfg.Station.ControlPort == 0 {
		cfg.Station.ControlPort = 7000
	}

	setupTLS()
	registerStation(cfg)
	go pollTunnels(cfg)
	go heartbeat(cfg)
	go cleanupUDPSessions()
	startControlServer(cfg)
}

func setupTLS() {
	dir := filepath.Dir(configPath())
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")

	if cert, err1 := os.ReadFile(certFile); err1 == nil {
		if key, err2 := os.ReadFile(keyFile); err2 == nil {
			certPEM = cert
			keyPEM = key
			computeFingerprint()
			return
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "reno-station"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}
	var cb, kb bytes.Buffer
	pem.Encode(&cb, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(&kb, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	certPEM = cb.Bytes()
	keyPEM = kb.Bytes()
	os.WriteFile(certFile, certPEM, 0600)
	os.WriteFile(keyFile, keyPEM, 0600)
	computeFingerprint()
}

func computeFingerprint() {
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("parse cert: %v", err)
	}
	fp := sha256.Sum256(cert.Raw)
	certFP = hex.EncodeToString(fp[:])
}

func registerStation(cfg Config) {
	ip := getPublicIP()
	body := map[string]interface{}{
		"name":             cfg.Station.Name,
		"control_port":     cfg.Station.ControlPort,
		"cert_fingerprint": certFP,
		"secret":           cfg.APISecret,
		"ip":               ip,
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post(cfg.DashboardURL+"/api/stations/register", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	var result struct {
		StationID string `json:"station_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("decode register: %v", err)
	}
	stationID = result.StationID
	log.Printf("Registered as station %s (name: %s, ip: %s)", stationID, cfg.Station.Name, ip)
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(data))
}

func startControlServer(cfg Config) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("tls keypair: %v", err)
	}
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", cfg.Station.ControlPort), &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		log.Fatalf("listen control: %v", err)
	}
	log.Printf("Station control port :%d", cfg.Station.ControlPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleEdge(conn, cfg)
	}
}

func handleEdge(conn net.Conn, cfg Config) {
	defer conn.Close()
	writer := protocol.NewWriter(conn)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	msg, err := protocol.ReadMessage(conn)
	if err != nil || msg.Type != protocol.MsgAuth {
		writer.WriteControl(protocol.MsgAuthFail, protocol.AuthFailMsg{Error: "expected auth"})
		return
	}
	var auth protocol.AuthMsg
	if err := msg.DecodeJSON(&auth); err != nil || auth.Secret != cfg.APISecret {
		writer.WriteControl(protocol.MsgAuthFail, protocol.AuthFailMsg{Error: "invalid secret"})
		return
	}
	conn.SetDeadline(time.Time{})

	edgeID := generateID()
	edge := &edgeConn{id: edgeID, writer: writer}
	edgesMu.Lock()
	edges[edgeID] = edge
	edgesMu.Unlock()
	defer func() {
		edgesMu.Lock()
		delete(edges, edgeID)
		edgesMu.Unlock()
		log.Printf("Edge %s disconnected", edgeID)
	}()

	writer.WriteControl(protocol.MsgAuthOK, protocol.AuthOKMsg{EdgeID: edgeID})
	log.Printf("Edge %s connected", edgeID)
	sendTunnelSync(edge)

	for {
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			return
		}
		switch msg.Type {

		case protocol.MsgChannelData:
			// Could be a TCP channel or UDP return packet from Edge
			tcpChannelsMu.RLock()
			ch, isTCP := tcpChannels[msg.ChannelID]
			tcpChannelsMu.RUnlock()

			if isTCP {
				// Stream data to external TCP client
				ch.mu.Lock()
				if !ch.closed {
					ch.conn.Write(msg.Payload)
				}
				ch.mu.Unlock()
			} else {
				// UDP response: send packet back to original source
				udpReturnMu.RLock()
				ret, isUDP := udpReturns[msg.ChannelID]
				udpReturnMu.RUnlock()
				if isUDP {
					ret.lastSeen = time.Now()
					ret.pc.WriteTo(msg.Payload, ret.srcAddr)
				}
			}

		case protocol.MsgChannelClose:
			var m protocol.ChannelCloseMsg
			msg.DecodeJSON(&m)
			closeTCPChannel(m.ChannelID)

		case protocol.MsgPing:
			writer.WriteControl(protocol.MsgPong, struct{}{})
		}
	}
}

func sendTunnelSync(edge *edgeConn) {
	tunnelsMu.RLock()
	t := make([]protocol.TunnelConfig, len(tunnels))
	copy(t, tunnels)
	tunnelsMu.RUnlock()
	edge.writer.WriteControl(protocol.MsgTunnelSync, protocol.TunnelSyncMsg{Tunnels: t})
}

func broadcastTunnelSync() {
	edgesMu.RLock()
	defer edgesMu.RUnlock()
	for _, edge := range edges {
		sendTunnelSync(edge)
	}
}

func pickEdge() *edgeConn {
	edgesMu.RLock()
	defer edgesMu.RUnlock()
	for _, e := range edges {
		return e
	}
	return nil
}

// ── TCP tunnel ────────────────────────────────────────────────────────────────

func closeTCPChannel(channelID uint32) {
	tcpChannelsMu.Lock()
	ch, ok := tcpChannels[channelID]
	if ok {
		ch.mu.Lock()
		ch.closed = true
		ch.conn.Close()
		ch.mu.Unlock()
		delete(tcpChannels, channelID)
	}
	tcpChannelsMu.Unlock()
}

func startTCPTunnelListener(t protocol.TunnelConfig) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", t.RemotePort))
	if err != nil {
		log.Printf("[TCP] listen %q :%d: %v", t.Name, t.RemotePort, err)
		return
	}
	tcpListenersMu.Lock()
	if old, ok := tcpListeners[t.ID]; ok {
		old.Close()
	}
	tcpListeners[t.ID] = ln
	tcpListenersMu.Unlock()
	log.Printf("[TCP] Tunnel %q listening on :%d", t.Name, t.RemotePort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleTCPTunnelConn(conn, t)
	}
}

func handleTCPTunnelConn(clientConn net.Conn, t protocol.TunnelConfig) {
	edge := pickEdge()
	if edge == nil {
		clientConn.Close()
		return
	}

	channelID := atomic.AddUint32(&channelCounter, 1)
	if err := edge.writer.WriteControl(protocol.MsgChannelOpen, protocol.ChannelOpenMsg{
		ChannelID: channelID,
		TunnelID:  t.ID,
		UDP:       false,
	}); err != nil {
		clientConn.Close()
		return
	}

	ch := &tcpChannel{conn: clientConn}
	tcpChannelsMu.Lock()
	tcpChannels[channelID] = ch
	tcpChannelsMu.Unlock()

	defer func() {
		closeTCPChannel(channelID)
		edge.writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: channelID})
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := clientConn.Read(buf)
		if n > 0 {
			edge.writer.WriteData(channelID, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// ── UDP tunnel ────────────────────────────────────────────────────────────────

// udpSession maps a remote source address to a channel ID for a given UDP listener.
type udpSession struct {
	channelID uint32
	lastSeen  time.Time
}

func startUDPTunnelListener(t protocol.TunnelConfig) {
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", t.RemotePort))
	if err != nil {
		log.Printf("[UDP] listen %q :%d: %v", t.Name, t.RemotePort, err)
		return
	}
	udpListenersMu.Lock()
	if old, ok := udpListeners[t.ID]; ok {
		old.Close()
	}
	udpListeners[t.ID] = pc
	udpListenersMu.Unlock()
	log.Printf("[UDP] Tunnel %q listening on :%d", t.Name, t.RemotePort)

	var sessionsMu sync.Mutex
	sessions := make(map[string]*udpSession) // srcAddr → session

	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		srcKey := src.String()

		sessionsMu.Lock()
		sess, exists := sessions[srcKey]
		if !exists {
			// new UDP session — open a channel to Edge
			edge := pickEdge()
			if edge == nil {
				sessionsMu.Unlock()
				continue
			}
			channelID := atomic.AddUint32(&channelCounter, 1)
			sess = &udpSession{channelID: channelID, lastSeen: time.Now()}
			sessions[srcKey] = sess

			// Register return path so Edge responses get sent back to src
			udpReturnMu.Lock()
			udpReturns[channelID] = &udpReturn{pc: pc, srcAddr: src, lastSeen: time.Now()}
			udpReturnMu.Unlock()

			edge.writer.WriteControl(protocol.MsgChannelOpen, protocol.ChannelOpenMsg{
				ChannelID: channelID,
				TunnelID:  t.ID,
				UDP:       true,
			})
		}
		sess.lastSeen = time.Now()
		channelID := sess.channelID
		sessionsMu.Unlock()

		// Forward packet to Edge
		edge := pickEdge()
		if edge != nil {
			edge.writer.WriteData(channelID, pkt)
		}
	}
}

// cleanupUDPSessions removes stale UDP channels (no activity for 60s).
func cleanupUDPSessions() {
	for {
		time.Sleep(30 * time.Second)
		cutoff := time.Now().Add(-60 * time.Second)
		udpReturnMu.Lock()
		for id, ret := range udpReturns {
			if ret.lastSeen.Before(cutoff) {
				delete(udpReturns, id)
			}
		}
		udpReturnMu.Unlock()
	}
}

// ── Tunnel lifecycle ──────────────────────────────────────────────────────────

func pollTunnels(cfg Config) {
	for {
		time.Sleep(10 * time.Second)
		if stationID == "" {
			continue
		}
		url := fmt.Sprintf("%s/api/stations/%s/tunnels?secret=%s", cfg.DashboardURL, stationID, cfg.APISecret)
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("poll tunnels: %v", err)
			continue
		}
		var result struct {
			Tunnels []protocol.TunnelConfig `json:"tunnels"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		tunnelsMu.Lock()
		changed := !tunnelsEqual(tunnels, result.Tunnels)
		tunnels = result.Tunnels
		tunnelsMu.Unlock()

		if changed {
			log.Printf("Tunnels updated: %d tunnel(s)", len(result.Tunnels))
			updateListeners(result.Tunnels)
			broadcastTunnelSync()
		}
	}
}

func tunnelsEqual(a, b []protocol.TunnelConfig) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].RemotePort != b[i].RemotePort || a[i].Protocol != b[i].Protocol {
			return false
		}
	}
	return true
}

func updateListeners(newTunnels []protocol.TunnelConfig) {
	newIDs := make(map[string]bool)
	for _, t := range newTunnels {
		newIDs[t.ID] = true
	}

	// Stop removed TCP listeners
	tcpListenersMu.Lock()
	for id, ln := range tcpListeners {
		if !newIDs[id] {
			ln.Close()
			delete(tcpListeners, id)
		}
	}
	tcpListenersMu.Unlock()

	// Stop removed UDP listeners
	udpListenersMu.Lock()
	for id, pc := range udpListeners {
		if !newIDs[id] {
			pc.Close()
			delete(udpListeners, id)
		}
	}
	udpListenersMu.Unlock()

	// Start new listeners
	for _, t := range newTunnels {
		t := t
		if t.IsUDP() {
			udpListenersMu.Lock()
			_, exists := udpListeners[t.ID]
			udpListenersMu.Unlock()
			if !exists {
				go startUDPTunnelListener(t)
			}
		} else {
			tcpListenersMu.Lock()
			_, exists := tcpListeners[t.ID]
			tcpListenersMu.Unlock()
			if !exists {
				go startTCPTunnelListener(t)
			}
		}
	}
}

func heartbeat(cfg Config) {
	for {
		time.Sleep(30 * time.Second)
		if stationID == "" {
			continue
		}
		url := fmt.Sprintf("%s/api/stations/%s/heartbeat?secret=%s", cfg.DashboardURL, stationID, cfg.APISecret)
		resp, err := http.Post(url, "application/json", nil)
		if err == nil {
			resp.Body.Close()
		}
	}
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─── Edge globals ─────────────────────────────────────────────────────────────

var (
	edgeTunnels []protocol.TunnelConfig

	localChannelsMu sync.RWMutex
	localChannels   = make(map[uint32]*localChannel)
)

type localChannel struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
	isUDP  bool
}

// ─── Edge ────────────────────────────────────────────────────────────────────

func runEdge() {
	cfg := loadConfig()
	if cfg.Edge.StationID == "" {
		log.Fatal("edge.station_id is not set in config")
	}
	if cfg.APISecret == "" {
		log.Fatal("api_secret is not set in config")
	}
	if cfg.DashboardURL == "" {
		log.Fatal("dashboard_url is not set in config")
	}

	log.Printf("Reno Edge starting, station: %s", cfg.Edge.StationID)
	backoff := time.Second
	for {
		if err := edgeRun(cfg); err != nil {
			log.Printf("Disconnected: %v. Reconnecting in %s...", err, backoff)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

func edgeRun(cfg Config) error {
	url := fmt.Sprintf("%s/api/stations/%s/connect?secret=%s", cfg.DashboardURL, cfg.Edge.StationID, cfg.APISecret)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("fetch station info: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		EncryptedInfo string `json:"encrypted_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode station info: %v", err)
	}

	plain, err := cryptoDecrypt(cfg.APISecret, result.EncryptedInfo)
	if err != nil {
		return fmt.Errorf("decrypt station info: %v", err)
	}

	parts := strings.SplitN(plain, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid station info format: %q", plain)
	}
	host, portStr, fingerprint := parts[0], parts[1], parts[2]
	port, _ := strconv.Atoi(portStr)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificates")
			}
			fp := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(fp[:]) != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch")
			}
			return nil
		},
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp",
		fmt.Sprintf("%s:%d", host, port), tlsCfg)
	if err != nil {
		return fmt.Errorf("dial station: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to station %s:%d", host, port)
	writer := protocol.NewWriter(conn)
	writer.WriteControl(protocol.MsgAuth, protocol.AuthMsg{Secret: cfg.APISecret, Version: "1"})

	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read auth response: %v", err)
	}
	if msg.Type == protocol.MsgAuthFail {
		var fail protocol.AuthFailMsg
		msg.DecodeJSON(&fail)
		return fmt.Errorf("auth failed: %s", fail.Error)
	}
	if msg.Type != protocol.MsgAuthOK {
		return fmt.Errorf("unexpected auth response: %d", msg.Type)
	}
	var authOK protocol.AuthOKMsg
	msg.DecodeJSON(&authOK)
	log.Printf("Authenticated as edge %s", authOK.EdgeID)

	for {
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			return fmt.Errorf("read: %v", err)
		}
		switch msg.Type {

		case protocol.MsgTunnelSync:
			var sync protocol.TunnelSyncMsg
			msg.DecodeJSON(&sync)
			edgeTunnels = sync.Tunnels
			names := make([]string, len(sync.Tunnels))
			for i, t := range sync.Tunnels {
				names[i] = fmt.Sprintf("%s(%s)", t.Name, t.Protocol)
			}
			log.Printf("Tunnel sync: %v", names)

		case protocol.MsgChannelOpen:
			var open protocol.ChannelOpenMsg
			msg.DecodeJSON(&open)
			if open.UDP {
				go handleLocalUDPChannel(open, writer)
			} else {
				go handleLocalTCPChannel(open, writer)
			}

		case protocol.MsgChannelData:
			localChannelsMu.RLock()
			ch, ok := localChannels[msg.ChannelID]
			localChannelsMu.RUnlock()
			if ok {
				ch.mu.Lock()
				if !ch.closed {
					ch.conn.Write(msg.Payload)
				}
				ch.mu.Unlock()
			}

		case protocol.MsgChannelClose:
			var m protocol.ChannelCloseMsg
			msg.DecodeJSON(&m)
			closeLocalChannel(m.ChannelID)

		case protocol.MsgPing:
			writer.WriteControl(protocol.MsgPong, struct{}{})
		}
	}
}

// ── Edge TCP channel ──────────────────────────────────────────────────────────

func handleLocalTCPChannel(open protocol.ChannelOpenMsg, writer *protocol.Writer) {
	tunnel := findTunnel(open.TunnelID)
	if tunnel == nil {
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	addr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Printf("[TCP] connect local %s: %v", addr, err)
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	ch := &localChannel{conn: conn, isUDP: false}
	localChannelsMu.Lock()
	localChannels[open.ChannelID] = ch
	localChannelsMu.Unlock()

	defer func() {
		closeLocalChannel(open.ChannelID)
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			writer.WriteData(open.ChannelID, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// ── Edge UDP channel ──────────────────────────────────────────────────────────

func handleLocalUDPChannel(open protocol.ChannelOpenMsg, writer *protocol.Writer) {
	tunnel := findTunnel(open.TunnelID)
	if tunnel == nil {
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	addr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	// net.Dial("udp") creates a connected UDP socket — gives a net.Conn interface
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		log.Printf("[UDP] connect local %s: %v", addr, err)
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	ch := &localChannel{conn: conn, isUDP: true}
	localChannelsMu.Lock()
	localChannels[open.ChannelID] = ch
	localChannelsMu.Unlock()

	defer func() {
		closeLocalChannel(open.ChannelID)
		// No CHANNEL_CLOSE for UDP — Station cleans up by timeout
	}()

	// Read response packets from local UDP service and forward back to Station
	buf := make([]byte, 65535)
	for {
		// Reset deadline on each packet (60s UDP session timeout)
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			writer.WriteData(open.ChannelID, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func findTunnel(id string) *protocol.TunnelConfig {
	for i := range edgeTunnels {
		if edgeTunnels[i].ID == id {
			return &edgeTunnels[i]
		}
	}
	return nil
}

func closeLocalChannel(channelID uint32) {
	localChannelsMu.Lock()
	ch, ok := localChannels[channelID]
	if ok {
		ch.mu.Lock()
		ch.closed = true
		ch.conn.Close()
		ch.mu.Unlock()
		delete(localChannels, channelID)
	}
	localChannelsMu.Unlock()
}
