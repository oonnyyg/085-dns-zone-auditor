package zone

import "sort"

// CNAMEResult describes the resolution of one CNAME record.
type CNAMEResult struct {
	Name      string   `json:"name"`
	Path      []string `json:"path"`
	Status    string   `json:"status"` // resolved | dangling | missing-address | loop | external | conflict
	Addresses []string `json:"addresses,omitempty"`
}

// MXResult describes the check of one MX record.
type MXResult struct {
	Name       string `json:"name"`
	Preference int64  `json:"preference"`
	Exchange   string `json:"exchange"`
	Status     string `json:"status"` // ok | no-address | is-alias | unverified-external
}

// Report is the final JSON report.
type Report struct {
	Zone     string        `json:"zone"`
	OK       bool          `json:"ok"`
	Problems []Problem     `json:"problems"`
	CNAMEs   []CNAMEResult `json:"cnames"`
	MX       []MXResult    `json:"mx"`
}

// Analyze resolves every CNAME chain and checks every MX record.
// conflicted is the set of node names that have CNAME conflicts; those
// nodes are not followed during resolution.
func (z *Zone) Analyze(problems []Problem, conflicted map[string]bool) *Report {
	rep := &Report{Zone: z.Name, Problems: problems}
	if rep.Problems == nil {
		rep.Problems = []Problem{}
	}
	sort.Slice(rep.Problems, func(i, j int) bool {
		a, b := rep.Problems[i], rep.Problems[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Message < b.Message
	})

	var cnameNames []string
	for name, node := range z.Nodes {
		if node.CNAME != "" {
			cnameNames = append(cnameNames, name)
		}
	}
	sort.Strings(cnameNames)

	for _, name := range cnameNames {
		res := CNAMEResult{Name: name, Path: []string{name}}
		if conflicted[name] {
			res.Status = "conflict"
			rep.CNAMEs = append(rep.CNAMEs, res)
			continue
		}
		seen := map[string]bool{name: true}
		current := name
		for {
			node := z.Nodes[current]
			target := node.CNAME
			res.Path = append(res.Path, target)
			if !InZone(target, z.Name) {
				res.Status = "external"
				break
			}
			if seen[target] {
				res.Status = "loop"
				break
			}
			seen[target] = true
			tnode := z.Nodes[target]
			if tnode == nil {
				res.Status = "dangling"
				break
			}
			if conflicted[target] {
				res.Status = "conflict"
				break
			}
			if tnode.CNAME != "" {
				current = target
				continue
			}
			if len(tnode.A) > 0 {
				res.Status = "resolved"
				res.Addresses = tnode.A
			} else {
				res.Status = "missing-address"
			}
			break
		}
		rep.CNAMEs = append(rep.CNAMEs, res)
	}
	if rep.CNAMEs == nil {
		rep.CNAMEs = []CNAMEResult{}
	}

	var mxNames []string
	for name, node := range z.Nodes {
		if len(node.MX) > 0 {
			mxNames = append(mxNames, name)
		}
	}
	sort.Strings(mxNames)
	for _, name := range mxNames {
		for _, mx := range z.Nodes[name].MX {
			res := MXResult{Name: name, Preference: mx.Preference, Exchange: mx.Exchange}
			if !InZone(mx.Exchange, z.Name) {
				res.Status = "unverified-external"
			} else {
				tnode := z.Nodes[mx.Exchange]
				switch {
				case tnode == nil:
					res.Status = "no-address"
				case tnode.CNAME != "":
					res.Status = "is-alias"
				case len(tnode.A) == 0:
					res.Status = "no-address"
				default:
					res.Status = "ok"
				}
			}
			rep.MX = append(rep.MX, res)
		}
	}
	if rep.MX == nil {
		rep.MX = []MXResult{}
	}

	rep.OK = len(rep.Problems) == 0 && !rep.hasFailures()
	return rep
}

func (r *Report) hasFailures() bool {
	for _, c := range r.CNAMEs {
		if c.Status == "dangling" || c.Status == "loop" || c.Status == "missing-address" || c.Status == "conflict" {
			return true
		}
	}
	for _, m := range r.MX {
		if m.Status == "no-address" || m.Status == "is-alias" {
			return true
		}
	}
	return false
}

// ConflictedNodes returns names with CNAME conflicts from the problem list.
func ConflictedNodes(problems []Problem) map[string]bool {
	m := map[string]bool{}
	for _, p := range problems {
		if p.Kind == "conflict" && p.Name != "" {
			m[p.Name] = true
		}
	}
	return m
}
