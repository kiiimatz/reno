package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kiiimatz/reno/pkg/crypto"
	"github.com/kiiimatz/reno/pkg/protocol"
)

type Config struct {
	StationID    string `json:"station_id"`
	DashboardURL string `json:"dashboard_url"`
	APISecret    string `json:"api_secret"`
}

type TunnelConfig = protocol.TunnelConfig

type localChannel struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

var (
	cfg     Config
	tunnels []TunnelConfig

	channelsMu sync.RWMutex
	channels   = make(map[uint32]*localChannel)
)

func main() {
	loadConfig()
	log.Printf("Reno Edge starting, connecting to station %s", cfg.StationID)

	for {
		if err := run(); err != nil {
			log.Printf("Connection lost: %v. Reconnecting in 5s...", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func loadConfig() {
	configFile := "edge.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	if data, err := os.ReadFile(configFile); err == nil {
		json.Unmarshal(data, &cfg)
	}

	if v := os.Getenv("RENO_STATION_ID"); v != "" {
		cfg.StationID = v
	}
	if v := os.Getenv("RENO_DASHBOARD_URL"); v != "" {
		cfg.DashboardURL = v
	}
	if v := os.Getenv("RENO_API_SECRET"); v != "" {
		cfg.APISecret = v
	}

	if cfg.StationID == "" {
		log.Fatal("station_id is required")
	}
	if cfg.DashboardURL == "" {
		log.Fatal("dashboard_url is required")
	}
	if cfg.APISecret == "" {
		log.Fatal("api_secret is required")
	}
}

func run() error {
	// fetch station connection info
	url := fmt.Sprintf("%s/api/stations/%s/connect?secret=%s", cfg.DashboardURL, cfg.StationID, cfg.APISecret)
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

	// decrypt: "host:port:fingerprint"
	plain, err := crypto.Decrypt(cfg.APISecret, result.EncryptedInfo)
	if err != nil {
		return fmt.Errorf("decrypt station info: %v", err)
	}

	parts := strings.SplitN(plain, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid station info format")
	}
	host, portStr, fingerprint := parts[0], parts[1], parts[2]
	port, _ := strconv.Atoi(portStr)

	// connect with TLS, verify fingerprint
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificates")
			}
			fp := sha256.Sum256(cs.PeerCertificates[0].Raw)
			actual := hex.EncodeToString(fp[:])
			if actual != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch")
			}
			return nil
		},
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("dial station: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to station at %s", addr)

	writer := protocol.NewWriter(conn)

	// send auth
	writer.WriteControl(protocol.MsgAuth, protocol.AuthMsg{
		Secret:  cfg.APISecret,
		Version: "1",
	})

	// expect AUTH_OK
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
		return fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	var authOK protocol.AuthOKMsg
	msg.DecodeJSON(&authOK)
	log.Printf("Authenticated as edge %s", authOK.EdgeID)

	// message loop
	for {
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			return fmt.Errorf("read: %v", err)
		}

		switch msg.Type {
		case protocol.MsgTunnelSync:
			var syncMsg protocol.TunnelSyncMsg
			msg.DecodeJSON(&syncMsg)
			tunnels = syncMsg.Tunnels
			log.Printf("Received %d tunnel configs", len(tunnels))

		case protocol.MsgChannelOpen:
			var open protocol.ChannelOpenMsg
			msg.DecodeJSON(&open)
			go handleChannelOpen(open, writer)

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
			var closeMsg protocol.ChannelCloseMsg
			msg.DecodeJSON(&closeMsg)
			closeChannel(closeMsg.ChannelID)

		case protocol.MsgPing:
			writer.WriteControl(protocol.MsgPong, struct{}{})
		}
	}
}

func handleChannelOpen(open protocol.ChannelOpenMsg, writer *protocol.Writer) {
	// find tunnel config
	var tunnel *TunnelConfig
	for i := range tunnels {
		if tunnels[i].ID == open.TunnelID {
			tunnel = &tunnels[i]
			break
		}
	}
	if tunnel == nil {
		log.Printf("Unknown tunnel ID: %s", open.TunnelID)
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	addr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Printf("Connect to local %s: %v", addr, err)
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	ch := &localChannel{conn: conn}
	channelsMu.Lock()
	channels[open.ChannelID] = ch
	channelsMu.Unlock()

	defer func() {
		closeChannel(open.ChannelID)
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
