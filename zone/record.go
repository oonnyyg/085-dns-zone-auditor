package zone

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Record is one DNS record as read from the input JSON file.
type Record struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	TTL        int64  `json:"ttl"`
	Data       string `json:"data,omitempty"`       // A: IPv4 address
	Target     string `json:"target,omitempty"`     // CNAME: target name
	Preference int64  `json:"preference,omitempty"` // MX: preference
	Exchange   string `json:"exchange,omitempty"`   // MX: exchange name
}

// Input is the top-level input document.
type Input struct {
	Zone    string   `json:"zone"`
	Records []Record `json:"records"`
}

// ParseInput decodes the input JSON document.
func ParseInput(data []byte) (*Input, error) {
	var in Input
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid input JSON: %w", err)
	}
	return &in, nil
}

// NormalizeName lower-cases a fully qualified domain name and validates it.
// Names must end with a dot, contain only letters, digits and hyphens in
// labels of 1-63 chars, labels may not start or end with a hyphen, and the
// total length without the trailing dot must not exceed 253.
func NormalizeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	if !strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("name %q is not fully qualified (missing trailing dot)", name)
	}
	lower := strings.ToLower(name)
	for _, r := range lower {
		if r > 127 {
			return "", fmt.Errorf("name %q contains non-ASCII characters", name)
		}
	}
	body := strings.TrimSuffix(lower, ".")
	if len(body) > 253 {
		return "", fmt.Errorf("name %q exceeds 253 characters", name)
	}
	if body == "" {
		return "", fmt.Errorf("name %q is the root label, not allowed here", name)
	}
	for _, label := range strings.Split(body, ".") {
		if err := validateLabel(label); err != nil {
			return "", fmt.Errorf("name %q: %w", name, err)
		}
	}
	return lower, nil
}

func validateLabel(label string) error {
	if len(label) < 1 || len(label) > 63 {
		return fmt.Errorf("label %q must be 1-63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q must not start or end with a hyphen", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("label %q contains invalid character %q", label, string(c))
		}
	}
	return nil
}

// InZone reports whether name is the zone itself or a label-wise subdomain.
func InZone(name, zone string) bool {
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}
