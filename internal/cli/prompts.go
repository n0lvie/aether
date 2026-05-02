package cli

// Localized prompt templates for the CLI interface.
// All user-facing strings are defined here for easy i18n.

// PromptSet holds all prompts for a given language.
type PromptSet struct {
	ActionRequired    string
	PressEnter        string
	Timeout           string
	Confirmed         string
	AutoDetected      string
	ExpectedDevice    string
	AutoDetectEnabled string
	AbortHint         string
	HardwareActions   map[string]string
}

// Prompts is a map of language → prompt set.
var Prompts = map[Language]PromptSet{
	LangRU: {
		ActionRequired:    "AETHER :: ТРЕБУЕТСЯ ДЕЙСТВИЕ ОПЕРАТОРА",
		PressEnter:        "Нажмите Enter после выполнения (или q для отмены)...",
		Timeout:           "Таймаут ожидания",
		Confirmed:         "Принято. Повторное сканирование оборудования...",
		AutoDetected:      "Устройство обнаружено автоматически!",
		ExpectedDevice:    "Ожидаемое устройство",
		AutoDetectEnabled: "Автодетект включён — устройство будет обнаружено автоматически",
		AbortHint:         "Для отмены введите 'q' или 'exit'",
		HardwareActions: map[string]string{
			"attach_lora":     "Подключите LoRa/Meshtastic трансивер к USB-порту",
			"attach_modem":    "Подключите USB-модем с активной SIM-картой",
			"connect_phone":   "Подключите аналоговую телефонную линию к модему",
			"attach_sdr":      "Подключите SDR-приёмник (RTL-SDR/HackRF) к USB-порту",
			"enable_hotspot":  "Включите Wi-Fi точку доступа на телефоне и подключите USB",
			"position_sdr":    "Направьте SDR-антенну на указанный азимут",
			"generic_network": "Обеспечьте любое сетевое подключение (Wi-Fi, Ethernet, USB-tethering)",
		},
	},
	LangEN: {
		ActionRequired:    "AETHER :: OPERATOR ACTION REQUIRED",
		PressEnter:        "Press Enter when done (or q to abort)...",
		Timeout:           "Waiting timeout",
		Confirmed:         "Confirmed. Rescanning hardware...",
		AutoDetected:      "Device auto-detected!",
		ExpectedDevice:    "Expected device",
		AutoDetectEnabled: "Auto-detect enabled — device will be detected automatically",
		AbortHint:         "Type 'q' or 'exit' to abort",
		HardwareActions: map[string]string{
			"attach_lora":     "Connect a LoRa/Meshtastic transceiver to a USB port",
			"attach_modem":    "Connect a USB modem with an active SIM card",
			"connect_phone":   "Connect an analog phone line to the modem",
			"attach_sdr":      "Connect an SDR receiver (RTL-SDR/HackRF) to a USB port",
			"enable_hotspot":  "Enable Wi-Fi hotspot on your phone and connect via USB",
			"position_sdr":    "Point the SDR antenna to the specified azimuth",
			"generic_network": "Establish any network connection (Wi-Fi, Ethernet, USB tethering)",
		},
	},
}

// GetPrompt returns the prompt set for the given language.
func GetPrompt(lang Language) PromptSet {
	if p, ok := Prompts[lang]; ok {
		return p
	}
	return Prompts[LangEN]
}

// GetHardwareAction returns the localized description for a hardware action.
func GetHardwareAction(lang Language, actionID string) string {
	p := GetPrompt(lang)
	if desc, ok := p.HardwareActions[actionID]; ok {
		return desc
	}
	return actionID
}
