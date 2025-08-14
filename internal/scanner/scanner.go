package scanner

import (
	"gitleaks-lite/internal/config"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
)

// Finding represents a secret that has been found.
type Finding struct {
	RuleID      string
	File        string
	StartLine   int
	Secret      string
	Commit      string
	Author      string
	Email       string
	Date        string
	Message     string
	CodeContext string
}

type Scanner struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Scan performs the detection on a single gitdiff file.
func (s *Scanner) Scan(file *gitdiff.File) []Finding {
	var findings []Finding
	if file == nil || file.PatchHeader == nil {
		return findings
	}

	for _, textFragment := range file.TextFragments {
		if textFragment == nil {
			continue
		}

		content := textFragment.Raw(gitdiff.OpAdd)
		lines := strings.Split(content, "\n")

		for i, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if strings.Contains(line, "gitleaks:allow") {
				continue
			}

			for _, rule := range s.cfg.Rules {
				matches := rule.Regex.FindAllStringSubmatch(line, -1)
				if matches == nil {
					continue
				}

				for _, match := range matches {
					secret := ""
					// Safely determine the secret.
					if len(match) > rule.SecretGroup {
						secret = match[rule.SecretGroup]
					}
					// If a specific group is requested but empty, or not set, use the full match.
					if secret == "" {
						secret = match[0]
					}
					if secret == "" {
						continue
					}

					start := i - 2
					if start < 0 {
						start = 0
					}
					end := i + 3
					if end > len(lines) {
						end = len(lines)
					}
					contextSnippet := strings.Join(lines[start:end], "\n")

					findings = append(findings, Finding{
						RuleID:      rule.ID,
						File:        file.NewName,
						StartLine:   int(textFragment.NewPosition) + i,
						Secret:      secret,
						Commit:      file.PatchHeader.SHA,
						Author:      file.PatchHeader.Author.Name,
						Email:       file.PatchHeader.Author.Email,
						Date:        file.PatchHeader.AuthorDate.String(),
						Message:     file.PatchHeader.Message(),
						CodeContext: contextSnippet,
					})
				}
			}
		}
	}
	return findings
}
