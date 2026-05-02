package cli

// Localized prompt templates for the CLI interface.
// All user-facing strings are defined here for easy i18n.

// PromptSet holds all prompts for a given language.
type PromptSet struct {
	HardwareActions   map[string]string
}

// Prompts is a map of language → prompt set.
var Prompts = map[Language]PromptSet{
	LangEN: {
		HardwareActions: map[string]string{
			"attach_lora":     "attach_lora_transceiver",
			"attach_modem":    "attach_usb_modem",
			"connect_phone":   "connect_analog_line",
			"attach_sdr":      "attach_sdr_rx",
			"enable_hotspot":  "enable_usb_tethering",
			"position_sdr":    "align_sdr_azimuth",
			"generic_network": "establish_link",
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
