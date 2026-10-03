package audit

import (
	"strconv"
	"strings"
)

type mxEntry struct {
	priority int
	target   string
}

type node struct {
	a     map[string]bool
	cname string
	mx    []mxEntry
	ttls  map[string]int64
	// conflict marks a CNAME owner that coexists with other types or has
	// more than one CNAME target.
	conflict bool
}

func newNode() *node {
	return &node{a: map[string]bool{}, ttls: map[string]int64{}}
}

// Run validates the input and builds the full report. It never performs
// network access: names outside the zone are reported as unverified.
func Run(in Input) Report {
	rep := Report{Problems: []Problem{}, CNAMEs: []CNAMEResult{}, MXResults: []MXResult{}}

	zone, err := normalizeName(in.Zone)
	if err != nil {
		rep.Problems = append(rep.Problems, Problem{Code: "invalid_zone", Message: err.Error()})
		rep.CNAMEs = []CNAMEResult{}
		rep.MXResults = []MXResult{}
		finalize(&rep)
		return rep
	}
	rep.Zone = zone

	nodes := map[string]*node{}
	type cnameRef struct{ name string }
	cnameOwners := map[string]bool{}
	mxSeen := map[string]bool{}
	var mxOrder []mxEntry
	mxOwnerOf := map[mxEntry]string{}

	get := func(n string) *node {
		nd, ok := nodes[n]
		if !ok {
			nd = newNode()
			nodes[n] = nd
		}
		return nd
	}
	addProblem := func(code, name, typ, msg string) {
		rep.Problems = append(rep.Problems, Problem{Code: code, Name: name, Type: typ, Message: msg})
	}

	for _, r := range in.Records {
		rtype := strings.ToUpper(r.Type)
		switch rtype {
		case "A", "CNAME", "MX":
		default:
			addProblem("unsupported_type", r.Name, r.Type, "unsupported record type (only A, CNAME, MX are allowed)")
			continue
		}
		name, err := normalizeName(r.Name)
		if err != nil {
			addProblem("invalid_name", r.Name, rtype, err.Error())
			continue
		}
		if !inZone(name, zone) {
			addProblem("out_of_zone", name, rtype, "record owner is not within the zone")
			continue
		}
		if r.TTL < 0 {
			addProblem("invalid_ttl", name, rtype, "TTL must be a non-negative integer")
			continue
		}

		nd := get(name)
		if prior, ok := nd.ttls[rtype]; ok && prior != r.TTL {
			addProblem("ttl_mismatch", name, rtype, "records of the same name and type must share one TTL")
		} else {
			nd.ttls[rtype] = r.TTL
		}

		switch rtype {
		case "A":
			if !parseIPv4(strings.TrimSpace(r.Data)) {
				addProblem("invalid_address", name, "A", "not a valid IPv4 address: "+r.Data)
				continue
			}
			nd.a[strings.TrimSpace(r.Data)] = true
		case "CNAME":
			target, err := normalizeName(r.Data)
			if err != nil {
				addProblem("invalid_target", name, "CNAME", err.Error())
				continue
			}
			if !cnameOwners[name] {
				cnameOwners[name] = true
				nd.cname = target
			} else if nd.cname != target {
				nd.conflict = true
				addProblem("cname_multiple_targets", name, "CNAME", "a name may have only one CNAME target")
			}
		case "MX":
			prio, rawTarget, err := parseMXData(r.Data)
			if err != nil {
				addProblem("invalid_mx", name, "MX", err.Error())
				continue
			}
			target, err := normalizeName(rawTarget)
			if err != nil {
				addProblem("invalid_target", name, "MX", err.Error())
				continue
			}
			e := mxEntry{priority: prio, target: target}
			key := name + "|" + strconv.Itoa(prio) + " " + target
			if !mxSeen[key] {
				mxSeen[key] = true
				nd.mx = append(nd.mx, e)
				mxOrder = append(mxOrder, e)
				mxOwnerOf[e] = name
			}
		}
	}

	// CNAME coexistence conflicts.
	for name := range cnameOwners {
		nd := nodes[name]
		if len(nd.a) > 0 || len(nd.mx) > 0 {
			nd.conflict = true
			addProblem("cname_coexists", name, "CNAME", "CNAME must not coexist with other record types")
		}
	}

	resolveChains(&rep, zone, nodes, cnameOwners)
	checkMX(&rep, zone, nodes, mxOrder, mxOwnerOf)
	finalize(&rep)
	return rep
}
