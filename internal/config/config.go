package config

import (
	_ "embed"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
)

//go:embed gitleaks.toml
var defaultRules string

// ViperConfig is a temporary struct to match the TOML structure for parsing.
type ViperConfig struct {
	Rules []struct {
		ID          string
		Description string
		Regex       string
		SecretGroup int
		Entropy     float64
		Keywords    []string
	}
}

type Rule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	SecretGroup int
	Keywords    []string
	Entropy     float64
}

type Config struct {
	Rules []Rule
}

func Load() (*Config, error) {
	var vc ViperConfig
	if _, err := toml.Decode(defaultRules, &vc); err != nil {
		return nil, err
	}

	var cfg Config
	for _, vr := range vc.Rules {
		re, err := regexp.Compile(vr.Regex)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to compile regex for rule %s", vr.ID)
			continue
		}

		newRule := Rule{
			ID:          vr.ID,
			Description: vr.Description,
			Regex:       re,
			SecretGroup: vr.SecretGroup,
			Keywords:    vr.Keywords,
			Entropy:     vr.Entropy,
		}
		cfg.Rules = append(cfg.Rules, newRule)
	}

	return &cfg, nil
}
