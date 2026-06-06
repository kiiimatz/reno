package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type MessageType uint8

const (
	MsgAuth         MessageType = 0x01
	MsgAuthOK       MessageType = 0x02
	MsgAuthFail     MessageType = 0x03
	MsgTunnelSync   MessageType = 0x04
	MsgChannelOpen  MessageType = 0x05
	MsgChannelClose MessageType = 0x06
	MsgChannelData  MessageType = 0x07
	MsgPing         MessageType = 0x08
	MsgPong         MessageType = 0x09
)

type AuthMsg struct {
	Secret  string `json:"secret"`
	Version string `json:"version"`
}

type AuthOKMsg struct {
	EdgeID string `json:"edge_id"`
}

type AuthFailMsg struct {
	Error string `json:"error"`
}

type TunnelConfig struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	LocalHost  string `json:"local_host"`
	LocalPort  int    `json:"local_port"`
	RemotePort int    `json:"remote_port"`
	Protocol   string `json:"protocol"`
}

// IsUDP returns true for protocols that need UDP transport.
// Everything else (TCP, HTTP, HTTPS, SSH, MySQL, Redis, …) uses TCP.
func (t TunnelConfig) IsUDP() bool {
	switch t.Protocol {
	case "UDP", "udp", "DNS", "dns", "WireGuard", "wireguard", "QUIC", "quic":
		return true
	}
	return false
}

type TunnelSyncMsg struct {
	Tunnels []TunnelConfig `json:"tunnels"`
}

type ChannelOpenMsg struct {
	ChannelID uint32 `json:"channel_id"`
	TunnelID  string `json:"tunnel_id"`
	UDP       bool   `json:"udp,omitempty"`
}

type ChannelCloseMsg struct {
	ChannelID uint32 `json:"channel_id"`
}

type Message struct {
	Type      MessageType
	ChannelID uint32
	Payload   []byte
}

// Writer is a mutex-protected writer for concurrent use
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (w *Writer) WriteControl(t MessageType, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	buf := make([]byte, 5+len(data))
	buf[0] = byte(t)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(data)))
	copy(buf[5:], data)
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(buf)
	return err
}

func (w *Writer) WriteData(channelID uint32, data []byte) error {
	buf := make([]byte, 9+len(data))
	buf[0] = byte(MsgChannelData)
	binary.BigEndian.PutUint32(buf[1:5], channelID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(data)))
	copy(buf[9:], data)
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(buf)
	return err
}

func ReadMessage(r io.Reader) (*Message, error) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return nil, err
	}
	t := MessageType(typeBuf[0])

	if t == MsgChannelData {
		header := make([]byte, 8)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, err
		}
		channelID := binary.BigEndian.Uint32(header[:4])
		length := binary.BigEndian.Uint32(header[4:8])
		if length > 1<<20 { // 1MB max
			return nil, fmt.Errorf("data frame too large: %d", length)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		return &Message{Type: t, ChannelID: channelID, Payload: data}, nil
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > 1<<20 {
		return nil, fmt.Errorf("control frame too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &Message{Type: t, Payload: payload}, nil
}

func (m *Message) DecodeJSON(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}
