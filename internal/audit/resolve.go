package audit

import "sort"

// ipv4Less compares dotted-quad addresses numerically, octet by octet.
func ipv4Less(a, b string) bool {
	var pa, pb int
	for k := 0; k < 4; k++ {
		x := readOctet(a, &pa)
		y := readOctet(b, &pb)
		if x != y {
			return x < y
		}
	}
	return false
}

func readOctet(s string, p *int) int {
	start := *p
	for *p < len(s) && s[*p] != '.' {
		*p++
	}
	v := 0
	for i := start; i < *p; i++ {
		v = v*10 + int(s[i]-'0')
	}
	*p++
	return v
}

func sortedAddresses(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for addr := range set {
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool { return ipv4Less(out[i], out[j]) })
	return out
}

func resolveChains(rep *Report, zone string, nodes map[string]*node, owners map[string]bool) {
	for name := range owners {
		rep.CNAMEs = append(rep.CNAMEs, traceChain(name, zone, nodes))
	}
	sort.Slice(rep.CNAMEs, func(i, j int) bool { return rep.CNAMEs[i].Name < rep.CNAMEs[j].Name })
}

// traceChain follows CNAME links starting at owner. Conflicting nodes stop
// resolution; a repeated node is a loop; a name outside the zone is
// external and never looked up.
func traceChain(owner, zone string, nodes map[string]*node) CNAMEResult {
	start := nodes[owner]
	res := CNAMEResult{Name: owner, Target: start.cname, Path: []string{owner}}

	if start.conflict {
		res.Status = "conflict"
		res.Detail = "conflicting CNAME node; chain not resolved"
		return res
	}

	visited := map[string]bool{owner: true}
	cur := start.cname
	for {
		if !inZone(cur, zone) {
			res.Path = append(res.Path, cur)
			res.Status = "external_unknown"
			res.Detail = "alias leaves the zone; not verified offline"
			return res
		}
		if visited[cur] {
			res.Path = append(res.Path, cur)
			res.Status = "loop"
			res.Detail = "alias chain revisits " + cur
			return res
		}
		visited[cur] = true
		res.Path = append(res.Path, cur)

		nd, ok := nodes[cur]
		if !ok {
			res.Status = "dangling"
			res.Detail = "terminal name has no records"
			return res
		}
		if nd.conflict {
			res.Status = "conflict"
			res.Detail = "chain reaches a conflicting CNAME node: " + cur
			return res
		}
		if nd.cname != "" {
			cur = nd.cname
			continue
		}
		if len(nd.a) > 0 {
			res.Status = "resolved"
			res.Addresses = sortedAddresses(nd.a)
			return res
		}
		if len(nd.mx) > 0 {
			res.Status = "no_address"
			res.Detail = "terminal name has records but no A address"
			return res
		}
		res.Status = "dangling"
		res.Detail = "terminal name has no records"
		return res
	}
}

func checkMX(rep *Report, zone string, nodes map[string]*node, order []mxEntry, ownerOf map[mxEntry]string) {
	for _, e := range order {
		res := MXResult{Name: ownerOf[e], Priority: e.priority, Target: e.target}
		if !inZone(e.target, zone) {
			res.Status = "external_unverified"
			res.Detail = "target outside the zone; not verified offline"
		} else if nd, ok := nodes[e.target]; !ok {
			res.Status = "missing"
			res.Detail = "MX target does not exist in the zone"
		} else if nd.cname != "" || nd.conflict {
			res.Status = "alias"
			res.Detail = "MX target must not be an alias"
		} else if len(nd.a) > 0 {
			res.Status = "resolved"
			res.Addresses = sortedAddresses(nd.a)
		} else {
			res.Status = "missing"
			res.Detail = "MX target has no direct A record"
		}
		rep.MXResults = append(rep.MXResults, res)
	}
	sort.SliceStable(rep.MXResults, func(i, j int) bool {
		a, b := rep.MXResults[i], rep.MXResults[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.Target < b.Target
	})
}
