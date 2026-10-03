package zone

import (
	"fmt"
	"net"
	"sort"
)

// Node holds the validated records of one owner name.
type Node struct {
	Name     string
	A        []string // sorted, de-duplicated IPv4 addresses
	CNAME    string   // single CNAME target, empty if none
	MX       []MXRecord
	HasOther bool // true if any record exists at this node
}

// MXRecord is a validated MX record.
type MXRecord struct {
	Preference int64
	Exchange   string
}

// Problem is a single diagnostic finding.
type Problem struct {
	Kind    string `json:"kind"` // conflict | loop | dangling | missing-address | invalid-record | ...
	Name    string `json:"name,omitempty"`
	Message string `json:"message"`
}

// Zone is the validated view of the input.
type Zone struct {
	Name  string
	Nodes map[string]*Node
}

// Build validates the input and constructs the zone model.
// All validation failures are collected as Problems; records that fail
// validation are excluded from the model.
func Build(in *Input) (*Zone, []Problem) {
	var problems []Problem
	zoneName, err := NormalizeName(in.Zone)
	if err != nil {
		return nil, []Problem{{Kind: "invalid-zone", Message: fmt.Sprintf("invalid zone name: %v", err)}}
	}
	z := &Zone{Name: zoneName, Nodes: map[string]*Node{}}

	type ttlKey struct{ name, typ string }
	ttlSeen := map[ttlKey]int64{}
	type recKey struct{ name, typ, value string }
	seen := map[recKey]bool{}

	for i, r := range in.Records {
		where := fmt.Sprintf("record #%d (%s %s)", i+1, r.Name, r.Type)
		name, err := NormalizeName(r.Name)
		if err != nil {
			problems = append(problems, Problem{Kind: "invalid-record", Name: r.Name,
				Message: fmt.Sprintf("%s: %v", where, err)})
			continue
		}
		if !InZone(name, zoneName) {
			problems = append(problems, Problem{Kind: "invalid-record", Name: name,
				Message: fmt.Sprintf("%s: owner name is outside zone %q", where, zoneName)})
			continue
		}
		typ := r.Type
		if typ != "A" && typ != "CNAME" && typ != "MX" {
			problems = append(problems, Problem{Kind: "invalid-record", Name: name,
				Message: fmt.Sprintf("%s: unsupported record type %q (only A, CNAME, MX)", where, r.Type)})
			continue
		}
		if r.TTL < 0 {
			problems = append(problems, Problem{Kind: "invalid-record", Name: name,
				Message: fmt.Sprintf("%s: negative TTL %d", where, r.TTL)})
			continue
		}
		key := ttlKey{name, typ}
		if prev, ok := ttlSeen[key]; ok && prev != r.TTL {
			problems = append(problems, Problem{Kind: "invalid-record", Name: name,
				Message: fmt.Sprintf("%s: inconsistent TTL for %s %s (%d vs %d)", where, name, typ, r.TTL, prev)})
			continue
		}
		ttlSeen[key] = r.TTL

		var value, exchange string
		switch typ {
		case "A":
			ip := net.ParseIP(r.Data)
			if ip == nil || ip.To4() == nil {
				problems = append(problems, Problem{Kind: "invalid-record", Name: name,
					Message: fmt.Sprintf("%s: invalid IPv4 address %q", where, r.Data)})
				continue
			}
			value = ip.To4().String()
		case "CNAME":
			target, err := NormalizeName(r.Target)
			if err != nil {
				problems = append(problems, Problem{Kind: "invalid-record", Name: name,
					Message: fmt.Sprintf("%s: invalid CNAME target: %v", where, err)})
				continue
			}
			value = target
		case "MX":
			if r.Preference < 0 || r.Preference > 65535 {
				problems = append(problems, Problem{Kind: "invalid-record", Name: name,
					Message: fmt.Sprintf("%s: MX preference %d out of range 0-65535", where, r.Preference)})
				continue
			}
			ex, err := NormalizeName(r.Exchange)
			if err != nil {
				problems = append(problems, Problem{Kind: "invalid-record", Name: name,
					Message: fmt.Sprintf("%s: invalid MX exchange: %v", where, err)})
				continue
			}
			exchange = ex
			value = fmt.Sprintf("%d %s", r.Preference, ex)
		}

		rk := recKey{name, typ, value}
		if seen[rk] {
			continue // identical record: merge silently
		}
		seen[rk] = true

		node := z.Nodes[name]
		if node == nil {
			node = &Node{Name: name}
			z.Nodes[name] = node
		}
		node.HasOther = true
		switch typ {
		case "A":
			node.A = append(node.A, value)
		case "CNAME":
			if node.CNAME == "" {
				node.CNAME = value
			} else if node.CNAME != value {
				problems = append(problems, Problem{Kind: "conflict", Name: name,
					Message: fmt.Sprintf("multiple CNAME targets at %s: %q and %q", name, node.CNAME, value)})
			}
		case "MX":
			node.MX = append(node.MX, MXRecord{Preference: r.Preference, Exchange: exchange})
		}
	}

	for _, node := range z.Nodes {
		sort.Strings(node.A)
		node.A = dedup(node.A)
		sort.Slice(node.MX, func(i, j int) bool {
			if node.MX[i].Preference != node.MX[j].Preference {
				return node.MX[i].Preference < node.MX[j].Preference
			}
			return node.MX[i].Exchange < node.MX[j].Exchange
		})
		if node.CNAME != "" && (len(node.A) > 0 || len(node.MX) > 0) {
			problems = append(problems, Problem{Kind: "conflict", Name: node.Name,
				Message: fmt.Sprintf("CNAME at %s coexists with other record types", node.Name)})
		}
	}
	return z, problems
}

func dedup(in []string) []string {
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
