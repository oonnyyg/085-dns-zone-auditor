package audit

import (
	"reflect"
	"testing"
)

func rec(name, typ string, ttl int64, data string) InputRecord {
	return InputRecord{Name: name, Type: typ, TTL: ttl, Data: data}
}

func codes(rep Report) map[string]bool {
	m := map[string]bool{}
	for _, p := range rep.Problems {
		m[p.Code] = true
	}
	return m
}

func findCNAME(rep Report, name string) (CNAMEResult, bool) {
	for _, c := range rep.CNAMEs {
		if c.Name == name {
			return c, true
		}
	}
	return CNAMEResult{}, false
}

func TestValidation(t *testing.T) {
	zone := "example.com."
	cases := []struct {
		name string
		rec  InputRecord
		code string
	}{
		{"relative name", rec("host.example.com", "A", 60, "1.2.3.4"), "invalid_name"},
		{"wildcard", rec("*.example.com.", "A", 60, "1.2.3.4"), "invalid_name"},
		{"non-ascii", rec("höst.example.com.", "A", 60, "1.2.3.4"), "invalid_name"},
		{"label too long", rec(string(make([]byte, 64))+".example.com.", "A", 60, "1.2.3.4"), "invalid_name"},
		{"hyphen edge", rec("-bad.example.com.", "A", 60, "1.2.3.4"), "invalid_name"},
		{"bad chars", rec("ba d.example.com.", "A", 60, "1.2.3.4"), "invalid_name"},
		{"bad type", rec("host.example.com.", "TXT", 60, "hello"), "unsupported_type"},
		{"bad ip", rec("host.example.com.", "A", 60, "1.2.3.999"), "invalid_address"},
		{"negative ttl", rec("host.example.com.", "A", -1, "1.2.3.4"), "invalid_ttl"},
		{"out of zone", rec("host.other.com.", "A", 60, "1.2.3.4"), "out_of_zone"},
		{"mx bad prio", rec("example.com.", "MX", 60, "70000 mail."), "invalid_mx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := Run(Input{Zone: zone, Records: []InputRecord{tc.rec}})
			if !codes(rep)[tc.code] {
				t.Fatalf("want code %s, got %+v", tc.code, rep.Problems)
			}
			if rep.OK {
				t.Fatal("report must not be OK")
			}
		})
	}
}

func TestCNAMEStatuses(t *testing.T) {
	zone := "example.com."
	rep := Run(Input{Zone: zone, Records: []InputRecord{
		rec("ok.example.com.", "CNAME", 60, "leaf.example.com."),
		rec("leaf.example.com.", "A", 60, "10.0.0.2"),
		rec("leaf.example.com.", "A", 60, "10.0.0.10"),

		rec("chain.example.com.", "CNAME", 60, "mid.example.com."),
		rec("mid.example.com.", "CNAME", 60, "leaf.example.com."),

		rec("dangling.example.com.", "CNAME", 60, "gone.example.com."),

		rec("noaddr.example.com.", "CNAME", 60, "onlymx.example.com."),
		rec("onlymx.example.com.", "MX", 60, "10 mail.example.net."),

		rec("ext.example.com.", "CNAME", 60, "target.other.net."),

		rec("loop1.example.com.", "CNAME", 60, "loop2.example.com."),
		rec("loop2.example.com.", "CNAME", 60, "loop1.example.com."),

		rec("conf.example.com.", "CNAME", 60, "leaf.example.com."),
		rec("conf.example.com.", "CNAME", 60, "other.example.com."),

		rec("coexist.example.com.", "CNAME", 60, "leaf.example.com."),
		rec("coexist.example.com.", "A", 60, "1.2.3.4"),
	}})

	want := map[string]struct {
		status string
		addrs  []string
		path   []string
	}{
		"ok.example.com.":       {"resolved", []string{"10.0.0.2", "10.0.0.10"}, []string{"ok.example.com.", "leaf.example.com."}},
		"chain.example.com.":    {"resolved", []string{"10.0.0.2", "10.0.0.10"}, []string{"chain.example.com.", "mid.example.com.", "leaf.example.com."}},
		"dangling.example.com.": {"dangling", nil, []string{"dangling.example.com.", "gone.example.com."}},
		"noaddr.example.com.":   {"no_address", nil, []string{"noaddr.example.com.", "onlymx.example.com."}},
		"ext.example.com.":      {"external_unknown", nil, []string{"ext.example.com.", "target.other.net."}},
		"loop1.example.com.":    {"loop", nil, []string{"loop1.example.com.", "loop2.example.com.", "loop1.example.com."}},
		"conf.example.com.":     {"conflict", nil, []string{"conf.example.com."}},
		"coexist.example.com.":  {"conflict", nil, []string{"coexist.example.com."}},
	}
	for name, w := range want {
		got, ok := findCNAME(rep, name)
		if !ok {
			t.Fatalf("missing CNAME result for %s", name)
		}
		if got.Status != w.status {
			t.Errorf("%s status = %s, want %s", name, got.Status, w.status)
		}
		if !reflect.DeepEqual(got.Addresses, w.addrs) {
			t.Errorf("%s addrs = %v, want %v", name, got.Addresses, w.addrs)
		}
		if !reflect.DeepEqual(got.Path, w.path) {
			t.Errorf("%s path = %v, want %v", name, got.Path, w.path)
		}
	}
}

func TestMXChecks(t *testing.T) {
	zone := "example.com."
	rep := Run(Input{Zone: zone, Records: []InputRecord{
		rec("good.example.com.", "A", 60, "192.168.0.1"),
		rec("alias.example.com.", "CNAME", 60, "good.example.com."),
		rec("example.com.", "MX", 60, "10 good.example.com."),
		rec("example.com.", "MX", 60, "20 alias.example.com."),
		rec("example.com.", "MX", 60, "30 missing.example.com."),
		rec("example.com.", "MX", 60, "40 relay.other.net."),
	}})
	byTarget := map[string]MXResult{}
	for _, m := range rep.MXResults {
		byTarget[m.Target] = m
	}
	want := map[string]string{
		"good.example.com.":    "resolved",
		"alias.example.com.":   "alias",
		"missing.example.com.": "missing",
		"relay.other.net.":     "external_unverified",
	}
	for target, status := range want {
		if got := byTarget[target]; got.Status != status {
			t.Errorf("%s = %s, want %s", target, got.Status, status)
		}
	}
}

func TestDedupTTLAndOrderIndependence(t *testing.T) {
	base := []InputRecord{
		rec("h.example.com.", "A", 60, "1.1.1.1"),
		rec("h.example.com.", "A", 60, "1.1.1.1"),
		rec("www.example.com.", "CNAME", 60, "h.example.com."),
	}
	rep1 := Run(Input{Zone: "example.com.", Records: base})
	shuffled := []InputRecord{base[2], base[1], base[0]}
	rep2 := Run(Input{Zone: "example.com.", Records: shuffled})

	if !rep1.OK || !rep2.OK {
		t.Fatalf("unexpected problems: %v %v", rep1.Problems, rep2.Problems)
	}
	if !reflect.DeepEqual(rep1, rep2) {
		t.Fatal("input order changed the conclusion")
	}
	c, _ := findCNAME(rep1, "www.example.com.")
	if !reflect.DeepEqual(c.Addresses, []string{"1.1.1.1"}) {
		t.Fatalf("addresses = %v", c.Addresses)
	}

	bad := Run(Input{Zone: "example.com.", Records: []InputRecord{
		rec("h.example.com.", "A", 60, "1.1.1.1"),
		rec("h.example.com.", "A", 300, "1.1.1.2"),
	}})
	if !codes(bad)["ttl_mismatch"] {
		t.Fatalf("want ttl_mismatch, got %v", bad.Problems)
	}
}

func TestCaseInsensitiveAndZoneApex(t *testing.T) {
	rep := Run(Input{Zone: "EXAMPLE.COM.", Records: []InputRecord{
		rec("WWW.Example.COM.", "CNAME", 60, "LEAF.example.com."),
		rec("leaf.EXAMPLE.com.", "A", 60, "2.2.2.2"),
		rec("EXAMPLE.COM.", "A", 60, "3.3.3.3"),
	}})
	if !rep.OK {
		t.Fatalf("unexpected problems: %v", rep.Problems)
	}
	if rep.Zone != "example.com." {
		t.Fatalf("zone = %q", rep.Zone)
	}
	c, ok := findCNAME(rep, "www.example.com.")
	if !ok || c.Status != "resolved" {
		t.Fatalf("cname = %+v", c)
	}
}
