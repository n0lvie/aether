// Package hwscan provides hardware discovery and capability enumeration.
// It scans COM/USB/Audio/Network interfaces to build a capability matrix
// used by the Orchestrator to determine which connectivity vectors are available.
package hwscan

// HardwareType represents a class of hardware device.
type HardwareType uint16

const (
	HWNone        HardwareType = 0
	HWCellModem   HardwareType = 1 << iota // AT-command compatible cellular modem
	HWLoRa                                 // LoRa/Meshtastic transceiver (USB serial)
	HWSDR                                  // Software Defined Radio (RTL-SDR, HackRF)
	HWAudioIn                              // Microphone (for ultrasonic RX)
	HWAudioOut                             // Speaker (for ultrasonic TX)
	HWPhoneLine                            // Analog phone line (for softmodem)
	HWWiFi                                 // Wi-Fi adapter
	HWWiFiMonitor                          // Wi-Fi adapter with monitor mode
	HWWiFiAware                            // Wi-Fi Aware (Android NAN)
	HWBLE                                  // Bluetooth Low Energy adapter
	HWAWDL                                 // Apple Wireless Direct Link
	HWEthernet                             // Wired ethernet
)

// String returns a human-readable name for a hardware type.
func (h HardwareType) String() string {
	names := map[HardwareType]string{
		HWCellModem:   "CellModem",
		HWLoRa:        "LoRa",
		HWSDR:         "SDR",
		HWAudioIn:     "AudioIn",
		HWAudioOut:    "AudioOut",
		HWPhoneLine:   "PhoneLine",
		HWWiFi:        "WiFi",
		HWWiFiMonitor: "WiFiMonitor",
		HWWiFiAware:   "WiFiAware",
		HWBLE:         "BLE",
		HWAWDL:        "AWDL",
		HWEthernet:    "Ethernet",
	}
	if name, ok := names[h]; ok {
		return name
	}
	return "Unknown"
}

// DeviceInfo describes a discovered hardware device.
type DeviceInfo struct {
	Type     HardwareType
	Path     string // OS device path: /dev/ttyUSB0, COM3, etc.
	Name     string // Human-readable device name
	VendorID uint16 // USB Vendor ID (0 if not USB)
	DeviceID uint16 // USB Device ID (0 if not USB)
}

// CapabilityMatrix is a bitmask of all available hardware.
// Used by the Orchestrator to filter vectors that can actually run.
type CapabilityMatrix struct {
	Mask    HardwareType
	Devices []DeviceInfo
}

// Has returns true if the given hardware type is available.
func (c *CapabilityMatrix) Has(hw HardwareType) bool {
	return c.Mask&hw != 0
}

// Add registers a discovered device and updates the bitmask.
func (c *CapabilityMatrix) Add(dev DeviceInfo) {
	c.Mask |= dev.Type
	c.Devices = append(c.Devices, dev)
}

// DevicesOfType returns all discovered devices of a given type.
func (c *CapabilityMatrix) DevicesOfType(hw HardwareType) []DeviceInfo {
	var result []DeviceInfo
	for _, d := range c.Devices {
		if d.Type == hw {
			result = append(result, d)
		}
	}
	return result
}
