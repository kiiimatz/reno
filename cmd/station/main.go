package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kiiimatz/reno/pkg/protocol"
)

type Config struct {
	Name         string `json:"name"`
	DashboardURL string `json:"dashboard_url"`
	APISecret    string `json:"api_secret"`
	ControlPort  int    `json:"control_port"`
}

type TunnelConfig = protocol.TunnelConfig

type channelInfo struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

type edgeConn struct {
	id      string
	writer  *protocol.Writer
	tunnels []TunnelConfig
}

var (
	cfg       Config
	stationID string
	certPEM   []byte
	keyPEM    []byte
	certFP    string

	edgesMu sync.RWMutex
	edges   = make(map[string]*edgeConn)

	channelsMu sync.RWMutex
	channels   = make(map[uint32]*channelInfo)

	channelCounter uint32

	tunnelsMu sync.RWMutex
	tunnels   []TunnelConfig

	listenersMu sync.Mutex
	listeners   = make(map[string]net.Listener)
)

func main() {
	// load config
	loadConfig()

	// generate or load TLS cert
	setupTLS()

	// register with dashboard
	registerWithDashboard()

	// start control server
	go startControlServer()

	// poll tunnels from dashboard
	go pollTunnels()

	// heartbeat
	go heartbeat()

	log.Printf("Reno Station %q started (control port: %d)", cfg.Name, cfg.ControlPort)
	select {} // block forever
}

func loadConfig() {
	// try config file first
	configFile := "station.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	if data, err := os.ReadFile(configFile); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("invalid config: %v", err)
		}
	}

	// override with env vars
	if v := os.Getenv("RENO_NAME"); v != "" {
		cfg.Name = v
	}
	if v := os.Getenv("RENO_DASHBOARD_URL"); v != "" {
		cfg.DashboardURL = v
	}
	if v := os.Getenv("RENO_API_SECRET"); v != "" {
		cfg.APISecret = v
	}
	if v := os.Getenv("RENO_CONTROL_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.ControlPort = p
		}
	}

	if cfg.ControlPort == 0 {
		cfg.ControlPort = 7000
	}
	if cfg.Name == "" {
		cfg.Name = "station"
	}
	if cfg.APISecret == "" {
		log.Fatal("api_secret is required")
	}
	if cfg.DashboardURL == "" {
		log.Fatal("dashboard_url is required")
	}
}

func setupTLS() {
	// try to load existing certs
	if cert, err1 := os.ReadFile("tls.crt"); err1 == nil {
		if key, err2 := os.ReadFile("tls.key"); err2 == nil {
			certPEM = cert
			keyPEM = key
			computeFingerprint()
			return
		}
	}

	// generate self-signed cert
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "reno-station"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	certBuf := &bytes.Buffer{}
	pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPEM = certBuf.Bytes()

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	keyBuf := &bytes.Buffer{}
	pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	keyPEM = keyBuf.Bytes()

	// save for reuse
	os.WriteFile("tls.crt", certPEM, 0600)
	os.WriteFile("tls.key", keyPEM, 0600)

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

func registerWithDashboard() {
	// get public IP
	ip := getPublicIP()

	body := map[string]interface{}{
		"name":             cfg.Name,
		"control_port":     cfg.ControlPort,
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
		log.Fatalf("decode register response: %v", err)
	}
	stationID = result.StationID
	log.Printf("Registered as station %s", stationID)
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return string(data)
}

func startControlServer() {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("tls keypair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", cfg.ControlPort), tlsCfg)
	if err != nil {
		log.Fatalf("listen control: %v", err)
	}
	log.Printf("Control server listening on :%d", cfg.ControlPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleEdge(conn)
	}
}

func handleEdge(conn net.Conn) {
	defer conn.Close()

	writer := protocol.NewWriter(conn)

	// expect AUTH within 10s
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

	conn.SetDeadline(time.Time{}) // clear deadline

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

	// send current tunnels
	sendTunnelSync(edge)

	// read loop
	for {
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			return
		}

		switch msg.Type {
		case protocol.MsgChannelData:
			channelsMu.RLock()
			ch, ok := channels[msg.ChannelID]
			channelsMu.RUnlock()
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
			closeChannel(m.ChannelID)
		case protocol.MsgPing:
			writer.WriteControl(protocol.MsgPong, struct{}{})
		}
	}
}

func sendTunnelSync(edge *edgeConn) {
	tunnelsMu.RLock()
	t := make([]TunnelConfig, len(tunnels))
	copy(t, tunnels)
	tunnelsMu.RUnlock()

	edge.tunnels = t
	edge.writer.WriteControl(protocol.MsgTunnelSync, protocol.TunnelSyncMsg{Tunnels: t})
}

func broadcastTunnelSync() {
	edgesMu.RLock()
	defer edgesMu.RUnlock()
	for _, edge := range edges {
		sendTunnelSync(edge)
	}
}

func openChannelToEdge(edgeID string, tunnelID string) (uint32, *edgeConn, error) {
	edgesMu.RLock()
	edge, ok := edges[edgeID]
	edgesMu.RUnlock()
	if !ok {
		return 0, nil, fmt.Errorf("edge not connected")
	}

	channelID := atomic.AddUint32(&channelCounter, 1)
	return channelID, edge, edge.writer.WriteControl(protocol.MsgChannelOpen, protocol.ChannelOpenMsg{
		ChannelID: channelID,
		TunnelID:  tunnelID,
	})
}

func closeChannel(channelID uint32) {
	channelsMu.Lock()
	ch, ok := channels[channelID]
	if ok {
		ch.mu.Lock()
		ch.closed = true
		ch.conn.Close()
		ch.mu.Unlock()
		delete(channels, channelID)
	}
	channelsMu.Unlock()
}

func startTunnelListener(t TunnelConfig) {
	addr := fmt.Sprintf(":%d", t.RemotePort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("listen tunnel %s port %d: %v", t.Name, t.RemotePort, err)
		return
	}

	listenersMu.Lock()
	if old, ok := listeners[t.ID]; ok {
		old.Close()
	}
	listeners[t.ID] = ln
	listenersMu.Unlock()

	log.Printf("Tunnel %q listening on :%d", t.Name, t.RemotePort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleTunnelConn(conn, t)
	}
}

func handleTunnelConn(clientConn net.Conn, t TunnelConfig) {
	// find a connected edge for this tunnel's station (we use first connected edge)
	edgesMu.RLock()
	var edge *edgeConn
	for _, e := range edges {
		edge = e
		break
	}
	edgesMu.RUnlock()

	if edge == nil {
		clientConn.Close()
		return
	}

	channelID, _, err := openChannelToEdge(edge.id, t.ID)
	if err != nil {
		clientConn.Close()
		return
	}

	ch := &channelInfo{conn: clientConn}
	channelsMu.Lock()
	channels[channelID] = ch
	channelsMu.Unlock()

	defer func() {
		closeChannel(channelID)
		edge.writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: channelID})
	}()

	// read from client, forward to edge
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

func pollTunnels() {
	for {
		time.Sleep(10 * time.Second)
		if stationID == "" {
			continue
		}
		fetchAndUpdateTunnels()
	}
}

func fetchAndUpdateTunnels() {
	url := fmt.Sprintf("%s/api/stations/%s/tunnels?secret=%s", cfg.DashboardURL, stationID, cfg.APISecret)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("fetch tunnels: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Tunnels []TunnelConfig `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("decode tunnels: %v", err)
		return
	}

	tunnelsMu.Lock()
	changed := !tunnelsEqual(tunnels, result.Tunnels)
	tunnels = result.Tunnels
	tunnelsMu.Unlock()

	if changed {
		log.Printf("Tunnels updated (%d tunnels)", len(result.Tunnels))
		updateListeners(result.Tunnels)
		broadcastTunnelSync()
	}
}

func tunnelsEqual(a, b []TunnelConfig) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].RemotePort != b[i].RemotePort {
			return false
		}
	}
	return true
}

func updateListeners(newTunnels []TunnelConfig) {
	newIDs := make(map[string]bool)
	for _, t := range newTunnels {
		newIDs[t.ID] = true
	}

	// stop removed tunnels
	listenersMu.Lock()
	for id, ln := range listeners {
		if !newIDs[id] {
			ln.Close()
			delete(listeners, id)
		}
	}
	listenersMu.Unlock()

	// start new tunnels
	for _, t := range newTunnels {
		listenersMu.Lock()
		_, exists := listeners[t.ID]
		listenersMu.Unlock()
		if !exists {
			go startTunnelListener(t)
		}
	}
}

func heartbeat() {
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
