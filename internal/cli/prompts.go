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
	LangEN: {
		ActionRequired:    "ACTION_REQUIRED",
		PressEnter:        "AWAITING_INPUT (ENTER: confirm, Q: abort)",
		Timeout:           "TIMEOUT",
		Confirmed:         "CONFIRMED. RESCANNING.",
		AutoDetected:      "AUTO_DETECTED",
		ExpectedDevice:    "EXPECTED",
		AutoDetectEnabled: "AUTO_DETECT_ACTIVE",
		AbortHint:         "ABORT_CMD: 'q'",
		HardwareActions: map[string]string{
			"attach_lora":     "CONNECT_LORA_USB",
			"attach_modem":    "CONNECT_MODEM_SIM",
			"connect_phone":   "CONNECT_ANALOG_PHONE",
			"attach_sdr":      "CONNECT_SDR_USB",
			"enable_hotspot":  "ENABLE_USB_HOTSPOT",
			"position_sdr":    "POSITION_SDR_ANTENNA",
			"generic_network": "ESTABLISH_NETWORK_LINK",
		},
	},
}

// GetPrompt returns the prompt set for the given language.
func GetPrompt(lang Language) PromptSet {
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
