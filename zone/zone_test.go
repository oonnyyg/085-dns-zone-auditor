package zone

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	valid := []string{
		"example.com.",
		"WWW.Example.COM.",
		"a-b.c-d.example.com.",
		strings.Repeat("a", 63) + ".com.",
	}
	for _, n := range valid {
		if _, err := NormalizeName(n); err != nil {
			t.Errorf("NormalizeName(%q) unexpected error: %v", n, err)
		}
	}
	invalid := []string{
		"example.com",                     // no trailing dot
		"",                                // empty
		".",                               // root
		"-bad.example.com.",               // leading hyphen
		"bad-.example.com.",               // trailing hyphen
		"bad_name.example.com.",           // underscore
		strings.Repeat("a", 64) + ".com.", // label too long
		strings.Repeat("a.", 130) + ".",   // too long overall
	}
	for _, n := range invalid {
		if _, err := NormalizeName(n); err == nil {
			t.Errorf("NormalizeName(%q) expected error", n)
		}
	}
	got, _ := NormalizeName("WWW.Example.COM.")
	if got != "www.example.com." {
		t.Errorf("case folding failed: %q", got)
	}
}

func TestInZone(t *testing.T) {
	if !InZone("example.com.", "example.com.") {
		t.Error("zone itself should be in zone")
	}
	if !InZone("www.example.com.", "example.com.") {
		t.Error("subdomain should be in zone")
	}
	if InZone("notexample.com.", "example.com.") {
		t.Error("suffix-only match must not count as subdomain")
	}
	if InZone("other.org.", "example.com.") {
		t.Error("outside name should not be in zone")
	}
}

func buildAndAnalyze(t *testing.T, in *Input) *Report {
	t.Helper()
	z, problems := Build(in)
	if z == nil {
		t.Fatalf("unexpected zone build failure: %+v", problems)
	}
	return z.Analyze(problems, ConflictedNodes(problems))
}

func TestResolvedCNAME(t *testing.T) {
	rep := buildAndAnalyze(t, &Input{
		Zone: "example.com.",
		Records: []Record{
			{Name: "www.example.com.", Type: "A", TTL: 300, Data: "192.0.2.1"},
			{Name: "www.example.com.", Type: "A", TTL: 300, Data: "192.0.2.2"},
			{Name: "www.example.com.", Type: "A", TTL: 300, Data: "192.0.2.1"}, // dup merged
			{Name: "web.example.com.", Type: "CNAME", TTL: 300, Target: "alias.example.com."},
			{Name: "alias.example.com.", Type: "CNAME", TTL: 300, Target: "WWW.example.com."},
		},
	})
	if !rep.OK {
		t.Fatalf("expected OK, got %+v", rep.Problems)
	}
	if len(rep.CNAMEs) != 2 {
		t.Fatalf("expected 2 cname results, got %d", len(rep.CNAMEs))
	}
	web := rep.CNAMEs[1] // sorted by name: alias < web
	if web.Name != "web.example.com." || web.Status != "resolved" {
		t.Fatalf("unexpected result: %+v", web)
	}
	wantPath := []string{"web.example.com.", "alias.example.com.", "www.example.com."}
	if strings.Join(web.Path, ",") != strings.Join(wantPath, ",") {
		t.Errorf("path = %v", web.Path)
	}
	if strings.Join(web.Addresses, ",") != "192.0.2.1,192.0.2.2" {
		t.Errorf("addresses = %v", web.Addresses)
	}
}

func TestDanglingLoopMissingExternal(t *testing.T) {
	rep := buildAndAnalyze(t, &Input{
		Zone: "example.com.",
		Records: []Record{
			{Name: "dangle.example.com.", Type: "CNAME", TTL: 1, Target: "gone.example.com."},
			{Name: "l1.example.com.", Type: "CNAME", TTL: 1, Target: "l2.example.com."},
			{Name: "l2.example.com.", Type: "CNAME", TTL: 1, Target: "l1.example.com."},
			{Name: "mxonly.example.com.", Type: "MX", TTL: 1, Preference: 10, Exchange: "mail.example.com."},
			{Name: "noaddr.example.com.", Type: "CNAME", TTL: 1, Target: "mxonly.example.com."},
			{Name: "ext.example.com.", Type: "CNAME", TTL: 1, Target: "other.org."},
			{Name: "mail.example.com.", Type: "A", TTL: 1, Data: "192.0.2.5"},
		},
	})
	if rep.OK {
		t.Fatal("expected failures")
	}
	status := map[string]string{}
	for _, c := range rep.CNAMEs {
		status[c.Name] = c.Status
	}
	if status["dangle.example.com."] != "dangling" {
		t.Errorf("dangle: %v", status)
	}
	if status["l1.example.com."] != "loop" || status["l2.example.com."] != "loop" {
		t.Errorf("loop: %v", status)
	}
	if status["noaddr.example.com."] != "missing-address" {
		t.Errorf("missing-address: %v", status)
	}
	if status["ext.example.com."] != "external" {
		t.Errorf("external: %v", status)
	}
}

func TestConflicts(t *testing.T) {
	rep := buildAndAnalyze(t, &Input{
		Zone: "example.com.",
		Records: []Record{
			{Name: "c.example.com.", Type: "CNAME", TTL: 1, Target: "a.example.com."},
			{Name: "c.example.com.", Type: "CNAME", TTL: 1, Target: "b.example.com."},
			{Name: "d.example.com.", Type: "CNAME", TTL: 1, Target: "a.example.com."},
			{Name: "d.example.com.", Type: "A", TTL: 1, Data: "192.0.2.9"},
			{Name: "a.example.com.", Type: "A", TTL: 1, Data: "192.0.2.1"},
		},
	})
	if rep.OK {
		t.Fatal("expected failures")
	}
	var conflicts int
	for _, p := range rep.Problems {
		if p.Kind == "conflict" {
			conflicts++
		}
	}
	if conflicts != 2 {
		t.Errorf("expected 2 conflicts, got %d: %+v", conflicts, rep.Problems)
	}
	for _, c := range rep.CNAMEs {
		if c.Status != "conflict" {
			t.Errorf("conflicted node %s should not resolve, got %s", c.Name, c.Status)
		}
	}
}

func TestMXChecks(t *testing.T) {
	rep := buildAndAnalyze(t, &Input{
		Zone: "example.com.",
		Records: []Record{
			{Name: "example.com.", Type: "MX", TTL: 1, Preference: 10, Exchange: "mail.example.com."},
			{Name: "example.com.", Type: "MX", TTL: 1, Preference: 20, Exchange: "alias.example.com."},
			{Name: "example.com.", Type: "MX", TTL: 1, Preference: 30, Exchange: "gone.example.com."},
			{Name: "example.com.", Type: "MX", TTL: 1, Preference: 40, Exchange: "mx.provider.net."},
			{Name: "mail.example.com.", Type: "A", TTL: 1, Data: "192.0.2.1"},
			{Name: "alias.example.com.", Type: "CNAME", TTL: 1, Target: "mail.example.com."},
		},
	})
	if rep.OK {
		t.Fatal("expected failures")
	}
	byPref := map[int64]string{}
	for _, m := range rep.MX {
		byPref[m.Preference] = m.Status
	}
	if byPref[10] != "ok" || byPref[20] != "is-alias" ||
		byPref[30] != "no-address" || byPref[40] != "unverified-external" {
		t.Errorf("mx statuses: %v", byPref)
	}
}

func TestInvalidRecords(t *testing.T) {
	rep := buildAndAnalyze(t, &Input{
		Zone: "example.com.",
		Records: []Record{
			{Name: "a.example.com.", Type: "AAAA", TTL: 1, Data: "::1"},     // unsupported type
			{Name: "a.example.com.", Type: "A", TTL: 1, Data: "999.1.1.1"},  // bad IP
			{Name: "a.example.com.", Type: "A", TTL: -5, Data: "192.0.2.1"}, // bad TTL
			{Name: "x.example.com.", Type: "MX", TTL: 1, Preference: 70000, Exchange: "m.example.com."},
			{Name: "out.org.", Type: "A", TTL: 1, Data: "192.0.2.1"}, // out of zone
			{Name: "t.example.com.", Type: "A", TTL: 100, Data: "192.0.2.1"},
			{Name: "t.example.com.", Type: "A", TTL: 200, Data: "192.0.2.2"}, // TTL mismatch
		},
	})
	if rep.OK {
		t.Fatal("expected failures")
	}
	if len(rep.Problems) != 6 {
		t.Errorf("expected 6 problems, got %d: %+v", len(rep.Problems), rep.Problems)
	}
}

func TestInputOrderIrrelevant(t *testing.T) {
	recs := []Record{
		{Name: "www.example.com.", Type: "A", TTL: 300, Data: "192.0.2.1"},
		{Name: "web.example.com.", Type: "CNAME", TTL: 300, Target: "www.example.com."},
		{Name: "example.com.", Type: "MX", TTL: 300, Preference: 10, Exchange: "www.example.com."},
	}
	rev := make([]Record, len(recs))
	for i, r := range recs {
		rev[len(recs)-1-i] = r
	}
	r1 := buildAndAnalyze(t, &Input{Zone: "example.com.", Records: recs})
	r2 := buildAndAnalyze(t, &Input{Zone: "example.com.", Records: rev})
	if !r1.OK || !r2.OK {
		t.Fatalf("expected OK: %+v / %+v", r1.Problems, r2.Problems)
	}
	if len(r1.CNAMEs) != len(r2.CNAMEs) || len(r1.MX) != len(r2.MX) {
		t.Fatal("result cardinality differs with input order")
	}
	for i := range r1.CNAMEs {
		if r1.CNAMEs[i].Name != r2.CNAMEs[i].Name || r1.CNAMEs[i].Status != r2.CNAMEs[i].Status {
			t.Errorf("cname result differs: %+v vs %+v", r1.CNAMEs[i], r2.CNAMEs[i])
		}
	}
}
