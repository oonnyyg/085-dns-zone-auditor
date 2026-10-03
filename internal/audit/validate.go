package audit

import (
	"strconv"
	"strings"
)

// normalizeName validates an absolute ASCII domain name (must end with a
// dot) and returns its canonical lower-cased form. Wildcards are rejected.
func normalizeName(raw string) (string, error) {
	if raw == "" {
		return "", &ValidationError{"name must not be empty"}
	}
	if strings.Contains(raw, "*") {
		return "", &ValidationError{"wildcard names are not supported: " + raw}
	}
	if !strings.HasSuffix(raw, ".") {
		return "", &ValidationError{"name must be an absolute name ending with a dot: " + raw}
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 128 {
			return "", &ValidationError{"name must be ASCII: " + raw}
		}
	}
	body := raw[:len(raw)-1]
	if len(body) > 253 {
		return "", &ValidationError{"name exceeds 253 characters without the trailing dot: " + raw}
	}
	labels := strings.Split(body, ".")
	for _, label := range labels {
		if l := len(label); l < 1 || l > 63 {
			return "", &ValidationError{"label must be 1 to 63 characters: " + raw}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", &ValidationError{"label must not start or end with a hyphen: " + raw}
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-') {
				return "", &ValidationError{"label may contain only letters, digits and hyphens: " + raw}
			}
		}
	}
	return strings.ToLower(raw), nil
}

// inZone reports whether name is the zone itself or a sub-domain of zone,
// split on label boundaries. Both arguments must be normalized names.
func inZone(name, zone string) bool {
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}

// parseIPv4 strictly validates a dotted-decimal IPv4 address.
func parseIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) < 1 || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
		v, err := strconv.Atoi(p)
		if err != nil || v > 255 {
			return false
		}
	}
	return true
}

// parseMXData parses "priority target-host".
func parseMXData(data string) (int, string, error) {
	fields := strings.Fields(data)
	if len(fields) != 2 {
		return 0, "", &ValidationError{"MX data must be \"priority target\": " + data}
	}
	prio, err := strconv.Atoi(fields[0])
	if err != nil || prio < 0 || prio > 65535 {
		return 0, "", &ValidationError{"MX priority must be an integer from 0 to 65535: " + fields[0]}
	}
	return prio, fields[1], nil
}

// ValidationError describes a malformed field in the input.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }
