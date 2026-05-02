package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// TransportID identifies the transport protocol for a seed node.
type TransportID uint8

const (
	TransportTCP     TransportID = 0x01
	TransportQUIC    TransportID = 0x02 // HTTP/3 + ECH
	TransportICMP    TransportID = 0x03
	TransportLoRa    TransportID = 0x04
	TransportBLE     TransportID = 0x05
	TransportWebRTC  TransportID = 0x06
	TransportDTN     TransportID = 0x07 // Delay-Tolerant Networking
	TransportSMS     TransportID = 0x08
	TransportAudio   TransportID = 0x09 // Ultrasonic / Softmodem
)

func (t TransportID) String() string {
	names := map[TransportID]string{
		TransportTCP:    "TCP",
		TransportQUIC:   "QUIC",
		TransportICMP:   "ICMP",
		TransportLoRa:   "LoRa",
		TransportBLE:    "BLE",
		TransportWebRTC: "WebRTC",
		TransportDTN:    "DTN",
		TransportSMS:    "SMS",
		TransportAudio:  "Audio",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
}

// SeedNode is the compact, wire-format representation of a bootstrap node.
// Format: PubKey(32) || TransportID(1) || IP(4 or 16) || Port(2) || Signature(64)
type SeedNode struct {
	PubKey      [32]byte    // Ed25519 public key
	Transport   TransportID // How to connect
	IP          net.IP      // IPv4 (4 bytes) or IPv6 (16 bytes)
	Port        uint16      // Transport port (0 for portless transports like BLE)
	Signature   [64]byte    // Ed25519 signature over PubKey||Transport||IP||Port
}

// MarshalBinary encodes a SeedNode to its compact wire format.
func (s *SeedNode) MarshalBinary() ([]byte, error) {
	ip4 := s.IP.To4()
	isIPv4 := ip4 != nil

	var ipLen int
	var ipBytes []byte
	if isIPv4 {
		ipLen = 4
		ipBytes = ip4
	} else {
		ipLen = 16
		ipBytes = s.IP.To16()
		if ipBytes == nil {
			return nil, fmt.Errorf("invalid IP address")
		}
	}

	// Total: 32 + 1 + ipLen + 2 + 64
	buf := make([]byte, 32+1+ipLen+2+64)
	copy(buf[0:32], s.PubKey[:])
	buf[32] = byte(s.Transport)
	copy(buf[33:33+ipLen], ipBytes)
	binary.BigEndian.PutUint16(buf[33+ipLen:35+ipLen], s.Port)
	copy(buf[35+ipLen:], s.Signature[:])

	return buf, nil
}

// UnmarshalSeedNode decodes a SeedNode from wire format.
// The caller must indicate if the IP is IPv4 (4 bytes) or IPv6 (16 bytes).
func UnmarshalSeedNode(data []byte, ipv6 bool) (*SeedNode, error) {
	ipLen := 4
	if ipv6 {
		ipLen = 16
	}
	expected := 32 + 1 + ipLen + 2 + 64
	if len(data) < expected {
		return nil, fmt.Errorf("seed node too short: %d < %d", len(data), expected)
	}

	s := &SeedNode{}
	copy(s.PubKey[:], data[0:32])
	s.Transport = TransportID(data[32])
	s.IP = make(net.IP, ipLen)
	copy(s.IP, data[33:33+ipLen])
	s.Port = binary.BigEndian.Uint16(data[33+ipLen : 35+ipLen])
	copy(s.Signature[:], data[35+ipLen:35+ipLen+64])

	return s, nil
}

// Envelope is an encrypted packet wrapper using ChaCha20-Poly1305.
// After the Noise handshake completes, all data flows through this format.
type Envelope struct {
	Version   uint8   // Protocol version (currently 0x01)
	SessionID [16]byte // Identifies the Noise session
	Counter   uint64  // Monotonic nonce counter (replay protection)
	Payload   []byte  // ChaCha20-Poly1305 encrypted data
	Tag       [16]byte // Poly1305 authentication tag
}

// MarshalBinary serializes an Envelope to wire format.
func (e *Envelope) MarshalBinary() ([]byte, error) {
	// Version(1) + SessionID(16) + Counter(8) + PayloadLen(4) + Payload(N) + Tag(16)
	buf := make([]byte, 1+16+8+4+len(e.Payload)+16)

	buf[0] = e.Version
	copy(buf[1:17], e.SessionID[:])
	binary.BigEndian.PutUint64(buf[17:25], e.Counter)
	binary.BigEndian.PutUint32(buf[25:29], uint32(len(e.Payload)))
	copy(buf[29:29+len(e.Payload)], e.Payload)
	copy(buf[29+len(e.Payload):], e.Tag[:])

	return buf, nil
}

// GenerateSessionID creates a random 16-byte session identifier.
func GenerateSessionID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}
