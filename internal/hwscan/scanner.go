package hwscan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Scanner discovers available hardware devices on the host system.
type Scanner struct {
	log *slog.Logger
}

// NewScanner creates a new hardware scanner.
func NewScanner(log *slog.Logger) *Scanner {
	return &Scanner{log: log}
}

// Scan performs parallel hardware discovery across all device classes.
// Returns a CapabilityMatrix with all discovered devices.
func (s *Scanner) Scan(ctx context.Context) *CapabilityMatrix {
	matrix := &CapabilityMatrix{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Each scanner runs as a goroutine — hardware probing can be slow.
	scanners := []struct {
		name string
		fn   func(context.Context) []DeviceInfo
	}{
		{"serial", s.scanSerial},
		{"network", s.scanNetwork},
		{"audio", s.scanAudio},
		{"usb", s.scanUSB},
	}

	for _, sc := range scanners {
		wg.Add(1)
		go func(name string, fn func(context.Context) []DeviceInfo) {
			defer wg.Done()

			s.log.Debug("scanning hardware class", "class", name)
			devices := fn(ctx)

			mu.Lock()
			for _, dev := range devices {
				matrix.Add(dev)
				s.log.Info("discovered device",
					"type", dev.Type.String(),
					"path", dev.Path,
					"name", dev.Name,
				)
			}
			mu.Unlock()
		}(sc.name, sc.fn)
	}

	wg.Wait()
	s.log.Info("hardware scan complete",
		"capabilities", fmt.Sprintf("0x%04X", uint16(matrix.Mask)),
		"device_count", len(matrix.Devices),
	)
	return matrix
}

// scanSerial enumerates COM/ttyUSB ports looking for AT-compatible modems
// and LoRa/Meshtastic devices.
func (s *Scanner) scanSerial(ctx context.Context) []DeviceInfo {
	var devices []DeviceInfo

	var patterns []string
	switch runtime.GOOS {
	case "linux":
		patterns = []string{"/dev/ttyUSB", "/dev/ttyACM", "/dev/ttyS"}
	case "windows":
		patterns = []string{"COM"}
	case "darwin":
		patterns = []string{"/dev/cu.usbserial", "/dev/cu.usbmodem"}
	}

	for _, pattern := range patterns {
		found := s.probeSerialPattern(ctx, pattern)
		devices = append(devices, found...)
	}
	return devices
}

// probeSerialPattern checks for serial devices matching a pattern.
func (s *Scanner) probeSerialPattern(ctx context.Context, pattern string) []DeviceInfo {
	var devices []DeviceInfo

	if runtime.GOOS == "windows" {
		// Probe COM1-COM32
		for i := 1; i <= 32; i++ {
			select {
			case <-ctx.Done():
				return devices
			default:
			}
			port := fmt.Sprintf("COM%d", i)
			if dev, ok := s.probeSerialPort(port); ok {
				devices = append(devices, dev)
			}
		}
	} else {
		// Probe /dev/ttyUSB0..15, etc.
		for i := 0; i < 16; i++ {
			select {
			case <-ctx.Done():
				return devices
			default:
			}
			port := fmt.Sprintf("%s%d", pattern, i)
			if _, err := os.Stat(port); err == nil {
				if dev, ok := s.probeSerialPort(port); ok {
					devices = append(devices, dev)
				}
			}
		}
	}
	return devices
}

// probeSerialPort attempts to identify a device on a serial port.
// Sends AT command and checks response to classify the device.
func (s *Scanner) probeSerialPort(port string) (DeviceInfo, bool) {
	// TODO: Open serial port, send "AT\r\n", check for "OK" response
	// If OK → classify as HWCellModem
	// If Meshtastic signature → classify as HWLoRa
	// For now, check if the port exists (Linux) or is accessible (Windows)
	s.log.Debug("probing serial port", "port", port)
	return DeviceInfo{}, false
}

// scanNetwork enumerates network interfaces.
func (s *Scanner) scanNetwork(ctx context.Context) []DeviceInfo {
	var devices []DeviceInfo

	// Check for Wi-Fi interfaces
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/sys/class/net")
		if err == nil {
			for _, entry := range entries {
				select {
				case <-ctx.Done():
					return devices
				default:
				}
				name := entry.Name()
				typePath := fmt.Sprintf("/sys/class/net/%s/type", name)
				data, err := os.ReadFile(typePath)
				if err != nil {
					continue
				}
				netType := strings.TrimSpace(string(data))

				// Type 1 = Ethernet, check wireless dir for WiFi
				wirelessPath := fmt.Sprintf("/sys/class/net/%s/wireless", name)
				if _, err := os.Stat(wirelessPath); err == nil {
					devices = append(devices, DeviceInfo{
						Type: HWWiFi,
						Path: name,
						Name: "WiFi: " + name,
					})
				} else if netType == "1" {
					devices = append(devices, DeviceInfo{
						Type: HWEthernet,
						Path: name,
						Name: "Ethernet: " + name,
					})
				}
			}
		}
	} else {
		// Cross-platform: assume at least one WiFi and one Ethernet
		// Real implementation would use OS-specific APIs
		devices = append(devices, DeviceInfo{
			Type: HWWiFi,
			Path: "default",
			Name: "Default WiFi Adapter",
		})
	}

	return devices
}

// scanAudio checks for audio input/output devices.
func (s *Scanner) scanAudio(ctx context.Context) []DeviceInfo {
	var devices []DeviceInfo

	if runtime.GOOS == "linux" {
		// Check ALSA/PulseAudio devices
		if _, err := os.Stat("/dev/snd"); err == nil {
			devices = append(devices, DeviceInfo{
				Type: HWAudioOut,
				Path: "/dev/snd",
				Name: "ALSA Audio Output",
			})
			devices = append(devices, DeviceInfo{
				Type: HWAudioIn,
				Path: "/dev/snd",
				Name: "ALSA Audio Input",
			})
		}
	} else {
		// Windows/macOS: assume audio is available
		devices = append(devices, DeviceInfo{
			Type: HWAudioOut,
			Path: "default",
			Name: "Default Audio Output",
		})
		devices = append(devices, DeviceInfo{
			Type: HWAudioIn,
			Path: "default",
			Name: "Default Audio Input",
		})
	}

	return devices
}

// scanUSB checks for USB devices (SDR, LoRa, etc.) by VID/PID.
func (s *Scanner) scanUSB(ctx context.Context) []DeviceInfo {
	// Known VID/PID pairs for target devices
	// RTL-SDR: 0x0bda:0x2838
	// HackRF: 0x1d50:0x6089
	// Meshtastic T-Beam: various ESP32 VID/PIDs

	// TODO: Use libusb or OS-specific USB enumeration
	// For now, return empty — real implementation requires CGo or syscalls
	return nil
}
