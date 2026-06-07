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
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	APIPort     int    `json:"api_port"` // default 8080
}

type EdgeConfig struct {
	// StationID is optional. Leave empty to auto-connect to the first
	// registered station on the dashboard.
	StationID string `json:"station_id"`
	// Name identifies this edge in the dashboard. Defaults to hostname.
	Name string `json:"name"`
}

func configPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "reno", "config.json")
	}
	home, _ := os.UserHomeDir()
	// When running under sudo, use the invoking user's home (not root's)
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			home = u.HomeDir
		}
	}
	return filepath.Join(home, ".config", "reno", "config.json")
}

func loadConfig() Config {
	// os.Args[2] can be an explicit config path (used when running as a service)
	path := configPath()
	if len(os.Args) > 2 && os.Args[2] != "" {
		path = os.Args[2]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config not found at %s. Run 'reno config' to set up.\n", path)
		os.Exit(1)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

var version = "dev"

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "station":
		installAndStart("station")
	case "edge":
		installAndStart("edge")
	case "down":
		runDown()
	case "remove":
		runRemove()
	case "version", "--version", "-v":
		fmt.Printf("reno %s\n", version)
	case "update":
		runUpdate()
	case "config":
		runConfig()
	// Internal subcommands used by the OS service manager — not shown in help
	case "station-daemon":
		runStationDaemon()
	case "edge-daemon":
		runEdgeDaemon()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("reno %s\n\n", version)
	fmt.Println("Usage:")
	fmt.Println("  reno station   Start Station in background (auto-start on boot)")
	fmt.Println("  reno edge      Start Edge in background (auto-start on boot)")
	fmt.Println("  reno down      Stop both Station and Edge")
	fmt.Println("  reno remove    Uninstall services and binary")
	fmt.Println("  reno update    Update to the latest version")
	fmt.Println("  reno version   Show version")
	fmt.Println("  reno config    Edit configuration")
}

// ─── Update ───────────────────────────────────────────────────────────────────

func runUpdate() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable path: %v", err)
	}
	exePath, _ = filepath.Abs(exePath)

	binaryName := fmt.Sprintf("reno-%s-%s", runtime.GOOS, runtime.GOARCH)
	downloadURL := "https://github.com/kiiimatz/reno/releases/latest/download/" + binaryName

	fmt.Printf("Current version: %s\n", version)
	fmt.Printf("Downloading %s...\n", downloadURL)

	resp, err := http.Get(downloadURL)
	if err != nil {
		log.Fatalf("download: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("download failed: HTTP %d", resp.StatusCode)
	}

	tmpPath := exePath + ".new"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatalf("create temp file: %v\nTry running with sudo.", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		log.Fatalf("write: %v", err)
	}
	f.Close()

	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
		log.Fatalf("replace binary: %v\nTry running with sudo.", err)
	}

	fmt.Println("Binary updated.")

	// Restart running services
	switch runtime.GOOS {
	case "linux":
		run("systemctl", "restart", "reno-station")
		run("systemctl", "restart", "reno-edge")
	case "darwin":
		stationPlist := "/Library/LaunchDaemons/com.kiiimatz.reno-station.plist"
		edgePlist := "/Library/LaunchDaemons/com.kiiimatz.reno-edge.plist"
		run("launchctl", "unload", stationPlist)
		run("launchctl", "load", stationPlist)
		run("launchctl", "unload", edgePlist)
		run("launchctl", "load", edgePlist)
	case "windows":
		run("schtasks", "/End", "/TN", "RenoStation")
		run("schtasks", "/End", "/TN", "RenoEdge")
		run("schtasks", "/Run", "/TN", "RenoStation")
		run("schtasks", "/Run", "/TN", "RenoEdge")
	}

	fmt.Println("Services restarted.")
}

// ─── Service management ───────────────────────────────────────────────────────

func installAndStart(component string) {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable path: %v", err)
	}
	exePath, _ = filepath.Abs(exePath)

	// Capture config path NOW (as the current user) so the service
	// can find it even when running as root/SYSTEM later.
	cfgPath, _ := filepath.Abs(configPath())

	switch runtime.GOOS {
	case "linux":
		installSystemd(component, exePath, cfgPath)
	case "darwin":
		installLaunchd(component, exePath, cfgPath)
	case "windows":
		installWinTask(component, exePath, cfgPath)
	default:
		log.Fatalf("unsupported OS: %s", runtime.GOOS)
	}

	if component == "station" {
		fmt.Println("Reno Stationing.")
	} else {
		fmt.Println("Reno Edging.")
	}
}

func runDown() {
	switch runtime.GOOS {
	case "linux":
		run("systemctl", "stop", "reno-station")
		run("systemctl", "stop", "reno-edge")
	case "darwin":
		run("launchctl", "unload", "/Library/LaunchDaemons/com.kiiimatz.reno-station.plist")
		run("launchctl", "unload", "/Library/LaunchDaemons/com.kiiimatz.reno-edge.plist")
	case "windows":
		run("schtasks", "/End", "/TN", "RenoStation")
		run("schtasks", "/End", "/TN", "RenoEdge")
	}
	fmt.Println("Reno stopped.")
}

func runRemove() {
	exePath, _ := os.Executable()
	exePath, _ = filepath.Abs(exePath)

	switch runtime.GOOS {
	case "linux":
		run("systemctl", "stop", "reno-station")
		run("systemctl", "stop", "reno-edge")
		run("systemctl", "disable", "reno-station")
		run("systemctl", "disable", "reno-edge")
		os.Remove("/etc/systemd/system/reno-station.service")
		os.Remove("/etc/systemd/system/reno-edge.service")
		run("systemctl", "daemon-reload")
	case "darwin":
		stationPlist := "/Library/LaunchDaemons/com.kiiimatz.reno-station.plist"
		edgePlist := "/Library/LaunchDaemons/com.kiiimatz.reno-edge.plist"
		run("launchctl", "unload", stationPlist)
		run("launchctl", "unload", edgePlist)
		os.Remove(stationPlist)
		os.Remove(edgePlist)
	case "windows":
		run("schtasks", "/End", "/TN", "RenoStation")
		run("schtasks", "/End", "/TN", "RenoEdge")
		run("schtasks", "/Delete", "/F", "/TN", "RenoStation")
		run("schtasks", "/Delete", "/F", "/TN", "RenoEdge")
	}

	// Remove the binary itself
	if err := os.Remove(exePath); err != nil {
		fmt.Printf("Warning: could not remove binary %s: %v\n", exePath, err)
	} else {
		fmt.Printf("Removed %s\n", exePath)
	}

	fmt.Println("Reno removed.")
}

// ── Linux systemd ─────────────────────────────────────────────────────────────

func installSystemd(component, exePath, cfgPath string) {
	svcName := "reno-" + component
	unit := fmt.Sprintf(`[Unit]
Description=Reno %s
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s %s-daemon %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, strings.Title(component), exePath, component, cfgPath)

	path := "/etc/systemd/system/" + svcName + ".service"
	if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
		log.Fatalf("write service file: %v\nTry running with sudo.", err)
	}
	run("systemctl", "daemon-reload")
	run("systemctl", "enable", svcName)
	run("systemctl", "restart", svcName)
}

// ── macOS launchd ─────────────────────────────────────────────────────────────

func installLaunchd(component, exePath, cfgPath string) {
	label := "com.kiiimatz.reno-" + component
	logPath := "/var/log/reno-" + component + ".log"
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>%s-daemon</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, label, exePath, component, cfgPath, logPath, logPath)

	plistPath := "/Library/LaunchDaemons/" + label + ".plist"
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		log.Fatalf("write plist: %v\nTry running with sudo.", err)
	}
	exec.Command("launchctl", "unload", plistPath).Run()
	run("launchctl", "load", plistPath)
}

// ── Windows Task Scheduler ────────────────────────────────────────────────────

func installWinTask(component, exePath, cfgPath string) {
	taskName := "Reno" + strings.Title(component)
	logPath := filepath.Join(filepath.Dir(cfgPath), component+".log")
	os.MkdirAll(filepath.Dir(logPath), 0700)

	exec.Command("schtasks", "/Delete", "/F", "/TN", taskName).Run()

	cmd := fmt.Sprintf(`"%s" %s-daemon "%s"`, exePath, component, cfgPath)
	run("schtasks", "/Create", "/F",
		"/TN", taskName,
		"/TR", cmd,
		"/SC", "ONSTART",
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
	)
	run("schtasks", "/Run", "/TN", taskName)
}

// run executes a command, ignoring errors (best-effort for service management).
func run(name string, args ...string) {
	exec.Command(name, args...).Run()
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
				// Empty = auto-connect to first station on dashboard
				StationID: "",
			},
		}
		data, _ := json.MarshalIndent(def, "", "  ")
		if err := os.WriteFile(path, data, 0600); err != nil {
			log.Fatalf("write config: %v", err)
		}
		fmt.Printf("Created config: %s\n", path)
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
		fmt.Printf("Edit manually: %s\n", path)
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

func cryptoEncrypt(secret, plaintext string) (string, error) {
	key := deriveKey(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// ─── Station globals ──────────────────────────────────────────────────────────

var (
	stationID string
	certPEM   []byte
	keyPEM    []byte
	certFP    string

	edgesMu sync.RWMutex
	edges   = make(map[string]*edgeConn)

	tcpChannelsMu sync.RWMutex
	tcpChannels   = make(map[uint32]*tcpChannel)

	udpReturnMu sync.RWMutex
	udpReturns  = make(map[uint32]*udpReturn)

	channelCounter uint32

	tunnelsMu sync.RWMutex
	tunnels   []protocol.TunnelConfig

	tcpListenersMu sync.Mutex
	tcpListeners   = make(map[string]net.Listener)

	udpListenersMu sync.Mutex
	udpListeners   = make(map[string]net.PacketConn)
)

// DashEdge represents a registered edge in the dashboard state.
type DashEdge struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RegisteredAt string `json:"registeredAt"`
	LastSeen     string `json:"lastSeen"`
	Status       string `json:"status"`
}

var (
	dashEdgesMu sync.RWMutex
	dashEdges   = make(map[string]*DashEdge)

	stationRegisteredAt string
)

type edgeConn struct {
	id              string
	dashboardEdgeID string
	writer          *protocol.Writer
}

type tcpChannel struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

type udpReturn struct {
	pc       net.PacketConn
	srcAddr  net.Addr
	lastSeen time.Time
}

// ─── Station daemon ───────────────────────────────────────────────────────────

func stateDir() string {
	return filepath.Dir(configPath())
}

func saveEdgesState() {
	dashEdgesMu.RLock()
	list := make([]*DashEdge, 0, len(dashEdges))
	for _, e := range dashEdges {
		list = append(list, e)
	}
	dashEdgesMu.RUnlock()
	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(filepath.Join(stateDir(), "edges.json"), data, 0600)
}

func saveTunnelsState() {
	tunnelsMu.RLock()
	data, _ := json.MarshalIndent(tunnels, "", "  ")
	tunnelsMu.RUnlock()
	os.WriteFile(filepath.Join(stateDir(), "tunnels.json"), data, 0600)
}

func initStation(cfg Config) {
	dir := stateDir()
	os.MkdirAll(dir, 0700)

	// Load or generate station ID
	idFile := filepath.Join(dir, "station_id")
	if data, err := os.ReadFile(idFile); err == nil {
		stationID = strings.TrimSpace(string(data))
	}
	if stationID == "" {
		stationID = generateID()
		os.WriteFile(idFile, []byte(stationID), 0600)
	}
	stationRegisteredAt = time.Now().Format(time.RFC3339)
	log.Printf("Station ID: %s", stationID)

	// Load edges
	if data, err := os.ReadFile(filepath.Join(dir, "edges.json")); err == nil {
		var list []*DashEdge
		if json.Unmarshal(data, &list) == nil {
			dashEdgesMu.Lock()
			for _, e := range list {
				dashEdges[e.ID] = e
			}
			dashEdgesMu.Unlock()
		}
	}

	// Load tunnels
	if data, err := os.ReadFile(filepath.Join(dir, "tunnels.json")); err == nil {
		var list []protocol.TunnelConfig
		if json.Unmarshal(data, &list) == nil {
			tunnelsMu.Lock()
			tunnels = list
			tunnelsMu.Unlock()
			log.Printf("Loaded %d tunnel(s) from disk", len(list))
		}
	}
}

func checkDashAPIAuth(r *http.Request, secret string) bool {
	if r.URL.Query().Get("secret") == secret {
		return true
	}
	if r.Header.Get("X-Reno-Secret") == secret {
		return true
	}
	return false
}

func startDashAPI(cfg Config) {
	apiPort := cfg.Station.APIPort
	if apiPort == 0 {
		apiPort = 8080
	}

	mux := http.NewServeMux()

	// GET /api/state
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if !checkDashAPIAuth(r, cfg.APISecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		now := time.Now()
		dashEdgesMu.RLock()
		edgeList := make([]*DashEdge, 0, len(dashEdges))
		for _, e := range dashEdges {
			ec := *e
			if now.Sub(mustParseTime(e.LastSeen)) > 45*time.Second {
				ec.Status = "offline"
			}
			edgeList = append(edgeList, &ec)
		}
		dashEdgesMu.RUnlock()

		tunnelsMu.RLock()
		tList := append([]protocol.TunnelConfig{}, tunnels...)
		tunnelsMu.RUnlock()

		station := map[string]interface{}{
			"id":              stationID,
			"name":            cfg.Station.Name,
			"controlPort":     cfg.Station.ControlPort,
			"certFingerprint": certFP,
			"registeredAt":    stationRegisteredAt,
			"lastSeen":        now.Format(time.RFC3339),
			"status":          "online",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"edges":    edgeList,
			"stations": []interface{}{station},
			"tunnels":  tList,
		})
	})

	// POST /api/stations/register — backward compat
	mux.HandleFunc("/api/stations/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if !checkDashAPIAuth(r, cfg.APISecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"station_id": stationID})
	})

	// /api/stations/{id}/heartbeat, /api/stations/{id}/offline, /api/stations/{id}/connect
	mux.HandleFunc("/api/stations/", func(w http.ResponseWriter, r *http.Request) {
		if !checkDashAPIAuth(r, cfg.APISecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		if m := matchPath(path, `/api/stations/`, `/heartbeat`); m != "" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			tunnelsMu.RLock()
			tList := append([]protocol.TunnelConfig{}, tunnels...)
			tunnelsMu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true, "station_id": stationID, "tunnels": tList,
			})
			return
		}

		if m := matchPath(path, `/api/stations/`, `/offline`); m != "" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}

		if m := matchPath(path, `/api/stations/`, `/connect`); m != "" {
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			ip := getPublicIP()
			plain := fmt.Sprintf("%s:%d:%s", ip, cfg.Station.ControlPort, certFP)
			encrypted, err := cryptoEncrypt(cfg.APISecret, plain)
			if err != nil {
				http.Error(w, `{"error":"encrypt failed"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{
				"encrypted_info": encrypted,
				"station_id":     stationID,
			})
			return
		}

		// DELETE /api/stations/:id
		if r.Method == http.MethodDelete {
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}

		http.NotFound(w, r)
	})

	// /api/edges/register and /api/edges/{id}/...
	mux.HandleFunc("/api/edges/", func(w http.ResponseWriter, r *http.Request) {
		if !checkDashAPIAuth(r, cfg.APISecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		if path == "/api/edges/register" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var body struct {
				Name   string `json:"name"`
				Secret string `json:"secret"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			now := time.Now().Format(time.RFC3339)

			dashEdgesMu.Lock()
			var edgeID string
			for _, e := range dashEdges {
				if e.Name == body.Name {
					edgeID = e.ID
					e.LastSeen = now
					e.Status = "online"
					break
				}
			}
			if edgeID == "" {
				edgeID = generateID()
				dashEdges[edgeID] = &DashEdge{
					ID:           edgeID,
					Name:         body.Name,
					RegisteredAt: now,
					LastSeen:     now,
					Status:       "online",
				}
			}
			dashEdgesMu.Unlock()
			saveEdgesState()
			json.NewEncoder(w).Encode(map[string]string{"edge_id": edgeID})
			return
		}

		// GET /api/edges (no trailing segment)
		if path == "/api/edges" {
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			now := time.Now()
			dashEdgesMu.RLock()
			list := make([]*DashEdge, 0, len(dashEdges))
			for _, e := range dashEdges {
				ec := *e
				if now.Sub(mustParseTime(e.LastSeen)) > 45*time.Second {
					ec.Status = "offline"
				}
				list = append(list, &ec)
			}
			dashEdgesMu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{"edges": list})
			return
		}

		if m := matchPath(path, `/api/edges/`, `/heartbeat`); m != "" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			now := time.Now().Format(time.RFC3339)
			dashEdgesMu.Lock()
			if e, ok := dashEdges[m]; ok {
				e.LastSeen = now
				e.Status = "online"
			}
			dashEdgesMu.Unlock()
			saveEdgesState()
			tunnelsMu.RLock()
			tList := append([]protocol.TunnelConfig{}, tunnels...)
			tunnelsMu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "tunnels": tList})
			return
		}

		if m := matchPath(path, `/api/edges/`, `/offline`); m != "" {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			dashEdgesMu.Lock()
			if e, ok := dashEdges[m]; ok {
				e.Status = "offline"
			}
			dashEdgesMu.Unlock()
			saveEdgesState()
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}

		// DELETE /api/edges/:id
		if r.Method == http.MethodDelete {
			// Extract ID from path /api/edges/{id}
			parts := strings.Split(strings.TrimPrefix(path, "/api/edges/"), "/")
			if len(parts) == 1 && parts[0] != "" {
				dashEdgesMu.Lock()
				delete(dashEdges, parts[0])
				dashEdgesMu.Unlock()
				saveEdgesState()
				json.NewEncoder(w).Encode(map[string]bool{"ok": true})
				return
			}
		}

		http.NotFound(w, r)
	})

	// /api/tunnels and /api/tunnels/{id}
	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		if !checkDashAPIAuth(r, cfg.APISecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			tunnelsMu.RLock()
			tList := append([]protocol.TunnelConfig{}, tunnels...)
			tunnelsMu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{"tunnels": tList})
			return
		}

		if r.Method == http.MethodPost {
			var body protocol.TunnelConfig
			json.NewDecoder(r.Body).Decode(&body)
			if body.ID == "" {
				body.ID = generateID()
			}
			if body.CreatedAt == "" {
				body.CreatedAt = time.Now().Format(time.RFC3339)
			}
			if body.Status == "" {
				body.Status = "idle"
			}
			tunnelsMu.Lock()
			tunnels = append(tunnels, body)
			cur := append([]protocol.TunnelConfig{}, tunnels...)
			tunnelsMu.Unlock()
			saveTunnelsState()
			updateListeners(cur)
			broadcastTunnelSync()
			json.NewEncoder(w).Encode(map[string]interface{}{"tunnel": body})
			return
		}

		http.NotFound(w, r)
	})

	mux.HandleFunc("/api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		if !checkDashAPIAuth(r, cfg.APISecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
			tunnelsMu.Lock()
			newList := tunnels[:0]
			for _, t := range tunnels {
				if t.ID != id {
					newList = append(newList, t)
				}
			}
			tunnels = newList
			cur := append([]protocol.TunnelConfig{}, tunnels...)
			tunnelsMu.Unlock()
			saveTunnelsState()
			updateListeners(cur)
			broadcastTunnelSync()
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}

		http.NotFound(w, r)
	})

	addr := fmt.Sprintf(":%d", apiPort)
	log.Printf("Station API listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("API server error: %v", err)
	}
}

// matchPath checks if path starts with prefix and ends with suffix,
// returning the segment in between (or "" if no match).
func matchPath(path, prefix, suffix string) string {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	mid := path[len(prefix) : len(path)-len(suffix)]
	if mid == "" || strings.Contains(mid, "/") {
		return ""
	}
	return mid
}

func mustParseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func runStationDaemon() {
	cfg := loadConfig()
	if cfg.Station.Name == "" {
		log.Fatal("station.name is not set in config")
	}
	if cfg.APISecret == "" {
		log.Fatal("api_secret is not set in config")
	}
	if cfg.Station.ControlPort == 0 {
		cfg.Station.ControlPort = 7000
	}

	setupTLS()
	initStation(cfg)
	go startDashAPI(cfg)
	go cleanupUDPSessions()

	tunnelsMu.RLock()
	cur := append([]protocol.TunnelConfig{}, tunnels...)
	tunnelsMu.RUnlock()
	if len(cur) > 0 {
		updateListeners(cur)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Printf("Shutting down station...")
		os.Exit(0)
	}()

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

	// Enable TCP keepalive to detect dropped connections quickly
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(15 * time.Second)
		}
	}

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
	edge := &edgeConn{id: edgeID, dashboardEdgeID: auth.DashboardEdgeID, writer: writer}
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
	log.Printf("Edge %s connected (dashboard_id: %q)", edgeID, auth.DashboardEdgeID)
	sendTunnelSync(edge)

	// Send periodic pings to keep the connection alive through NAT/firewalls
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := writer.WriteControl(protocol.MsgPing, struct{}{}); err != nil {
				return
			}
		}
	}()

	for {
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		switch msg.Type {
		case protocol.MsgChannelData:
			tcpChannelsMu.RLock()
			ch, isTCP := tcpChannels[msg.ChannelID]
			tcpChannelsMu.RUnlock()
			if isTCP {
				ch.mu.Lock()
				if !ch.closed {
					ch.conn.Write(msg.Payload)
				}
				ch.mu.Unlock()
			} else {
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
		case protocol.MsgPong:
			// keepalive reply, nothing to do
		}
	}
}

func sendTunnelSync(edge *edgeConn) {
	tunnelsMu.RLock()
	var t []protocol.TunnelConfig
	for _, tc := range tunnels {
		// If edge has no dashboard ID (registration failed), send all tunnels as fallback.
		// Otherwise only send tunnels targeting this specific edge.
		if edge.dashboardEdgeID == "" || tc.EdgeID == "" || tc.EdgeID == edge.dashboardEdgeID {
			t = append(t, tc)
		}
	}
	tunnelsMu.RUnlock()
	if t == nil {
		t = []protocol.TunnelConfig{}
	}
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
	log.Printf("[TCP] Tunnel %q on :%d", t.Name, t.RemotePort)

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
	log.Printf("[UDP] Tunnel %q on :%d", t.Name, t.RemotePort)

	var sessionsMu sync.Mutex
	sessions := make(map[string]*udpSession)

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
			edge := pickEdge()
			if edge == nil {
				sessionsMu.Unlock()
				continue
			}
			channelID := atomic.AddUint32(&channelCounter, 1)
			sess = &udpSession{channelID: channelID, lastSeen: time.Now()}
			sessions[srcKey] = sess
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

		if edge := pickEdge(); edge != nil {
			edge.writer.WriteData(channelID, pkt)
		}
	}
}

type udpSession struct {
	channelID uint32
	lastSeen  time.Time
}

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
	tcpListenersMu.Lock()
	for id, ln := range tcpListeners {
		if !newIDs[id] {
			ln.Close()
			delete(tcpListeners, id)
		}
	}
	tcpListenersMu.Unlock()
	udpListenersMu.Lock()
	for id, pc := range udpListeners {
		if !newIDs[id] {
			pc.Close()
			delete(udpListeners, id)
		}
	}
	udpListenersMu.Unlock()
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


func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─── Edge globals ─────────────────────────────────────────────────────────────

var (
	edgeTunnels     []protocol.TunnelConfig
	dashboardEdgeID string

	localChannelsMu sync.RWMutex
	localChannels   = make(map[uint32]*localChannel)

	// pendingChannels buffers data for TCP channels that are still being set up.
	// This prevents data loss when MsgChannelData arrives before handleLocalTCPChannel
	// has finished dialing the local service and registering in localChannels.
	pendingChannelsMu sync.RWMutex
	pendingChannels   = make(map[uint32]*pendingCh)
)

type localChannel struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

// pendingCh accumulates MsgChannelData payloads arriving before the local
// TCP connection is established.
type pendingCh struct {
	mu     sync.Mutex
	buf    [][]byte
	closed bool
}

func (p *pendingCh) add(data []byte) {
	p.mu.Lock()
	if !p.closed {
		cp := make([]byte, len(data))
		copy(cp, data)
		p.buf = append(p.buf, cp)
	}
	p.mu.Unlock()
}

// closeAndFlush marks the pending buffer closed and writes any buffered data
// to the local channel. Must be called while ch is already registered in
// localChannels so concurrent writers use ch.mu for ordering.
func (p *pendingCh) closeAndFlush(ch *localChannel) {
	p.mu.Lock()
	p.closed = true
	buf := p.buf
	p.buf = nil
	p.mu.Unlock()

	if len(buf) == 0 {
		return
	}
	ch.mu.Lock()
	if !ch.closed {
		for _, data := range buf {
			ch.conn.Write(data)
		}
	}
	ch.mu.Unlock()
}

// ─── Edge daemon ──────────────────────────────────────────────────────────────

func markEdgeOffline(cfg Config) {
	if dashboardEdgeID == "" {
		return
	}
	url := fmt.Sprintf("%s/api/edges/%s/offline?secret=%s", cfg.DashboardURL, dashboardEdgeID, cfg.APISecret)
	resp, err := http.Post(url, "application/json", nil)
	if err == nil {
		resp.Body.Close()
	}
}

func registerEdgeWithDashboard(cfg Config, name string) {
	body := map[string]interface{}{
		"name":   name,
		"secret": cfg.APISecret,
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post(cfg.DashboardURL+"/api/edges/register", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("edge register: %v", err)
		return
	}
	defer resp.Body.Close()
	var result struct {
		EdgeID string `json:"edge_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.EdgeID == "" {
		log.Printf("edge register decode: %v", err)
		return
	}
	dashboardEdgeID = result.EdgeID
	log.Printf("Registered as edge %s (name: %s)", dashboardEdgeID, name)
}

func edgeHeartbeatLoop(cfg Config) {
	doHeartbeat := func() {
		if dashboardEdgeID == "" {
			return
		}
		url := fmt.Sprintf("%s/api/edges/%s/heartbeat?secret=%s", cfg.DashboardURL, dashboardEdgeID, cfg.APISecret)
		resp, err := http.Post(url, "application/json", nil)
		if err == nil {
			resp.Body.Close()
		}
	}
	// Send immediately on startup
	doHeartbeat()
	for {
		time.Sleep(5 * time.Second)
		doHeartbeat()
	}
}

func runEdgeDaemon() {
	cfg := loadConfig()
	if cfg.APISecret == "" {
		log.Fatal("api_secret is not set in config")
	}
	if cfg.DashboardURL == "" {
		log.Fatal("dashboard_url is not set in config")
	}

	edgeName := cfg.Edge.Name
	if edgeName == "" {
		edgeName, _ = os.Hostname()
	}

	registerEdgeWithDashboard(cfg, edgeName)
	go edgeHeartbeatLoop(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Printf("Shutting down, marking edge offline...")
		markEdgeOffline(cfg)
		os.Exit(0)
	}()

	// Use "auto" when station_id is not specified — connects to first station
	stationRef := cfg.Edge.StationID
	if stationRef == "" {
		stationRef = "auto"
	}

	log.Printf("Reno Edge starting (station: %s)", stationRef)
	backoff := time.Second
	for {
		if err := edgeRun(cfg, stationRef); err != nil {
			log.Printf("Disconnected: %v. Reconnecting in %s...", err, backoff)
			time.Sleep(backoff)
			if backoff < 5*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

func edgeRun(cfg Config, stationRef string) error {
	url := fmt.Sprintf("%s/api/stations/%s/connect?secret=%s", cfg.DashboardURL, stationRef, cfg.APISecret)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("fetch station info: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		EncryptedInfo string `json:"encrypted_info"`
		StationID     string `json:"station_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode station info: %v", err)
	}

	plain, err := cryptoDecrypt(cfg.APISecret, result.EncryptedInfo)
	if err != nil {
		return fmt.Errorf("decrypt station info: %v", err)
	}

	// plain = "host:port:fingerprint"
	parts := strings.SplitN(plain, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid station info: %q", plain)
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

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 15 * time.Second,
	}, "tcp", fmt.Sprintf("%s:%d", host, port), tlsCfg)
	if err != nil {
		return fmt.Errorf("dial station: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to station %s:%d", host, port)
	writer := protocol.NewWriter(conn)
	writer.WriteControl(protocol.MsgAuth, protocol.AuthMsg{Secret: cfg.APISecret, Version: "1", DashboardEdgeID: dashboardEdgeID})

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
			log.Printf("Tunnel sync: %d tunnel(s)", len(edgeTunnels))

		case protocol.MsgChannelOpen:
			var open protocol.ChannelOpenMsg
			msg.DecodeJSON(&open)
			if open.UDP {
				go handleLocalUDPChannel(open, writer)
			} else {
				// Register pending buffer BEFORE starting the goroutine so that
				// any MsgChannelData arriving during dial doesn't get dropped.
				pch := &pendingCh{}
				pendingChannelsMu.Lock()
				pendingChannels[open.ChannelID] = pch
				pendingChannelsMu.Unlock()
				go handleLocalTCPChannel(open, pch, writer)
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
			} else {
				// Channel is still being set up — buffer the data.
				pendingChannelsMu.RLock()
				pch, isPending := pendingChannels[msg.ChannelID]
				pendingChannelsMu.RUnlock()
				if isPending {
					pch.add(msg.Payload)
				}
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

func handleLocalTCPChannel(open protocol.ChannelOpenMsg, pch *pendingCh, writer *protocol.Writer) {
	removePending := func() {
		pendingChannelsMu.Lock()
		delete(pendingChannels, open.ChannelID)
		pendingChannelsMu.Unlock()
	}

	tunnel := findTunnel(open.TunnelID)
	if tunnel == nil {
		removePending()
		pch.mu.Lock(); pch.closed = true; pch.mu.Unlock()
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}
	addr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Printf("[TCP] connect %s: %v", addr, err)
		removePending()
		pch.mu.Lock(); pch.closed = true; pch.mu.Unlock()
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}

	// Register in localChannels FIRST so concurrent MsgChannelData handlers
	// write directly here instead of buffering.
	ch := &localChannel{conn: conn}
	localChannelsMu.Lock()
	localChannels[open.ChannelID] = ch
	localChannelsMu.Unlock()

	// Remove from pending and flush any buffered data into the local conn.
	removePending()
	pch.closeAndFlush(ch)

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

func handleLocalUDPChannel(open protocol.ChannelOpenMsg, writer *protocol.Writer) {
	tunnel := findTunnel(open.TunnelID)
	if tunnel == nil {
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}
	addr := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		log.Printf("[UDP] connect %s: %v", addr, err)
		writer.WriteControl(protocol.MsgChannelClose, protocol.ChannelCloseMsg{ChannelID: open.ChannelID})
		return
	}
	ch := &localChannel{conn: conn}
	localChannelsMu.Lock()
	localChannels[open.ChannelID] = ch
	localChannelsMu.Unlock()

	defer closeLocalChannel(open.ChannelID)

	buf := make([]byte, 65535)
	for {
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
