// Command zonecheck performs an offline audit of a small DNS zone:
// it validates A/CNAME/MX records, traces CNAME chains to their terminal,
// and flags conflicts, loops and dangling references. It never sends DNS
// queries; names outside the zone are reported as unverified.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/dns-zone-auditor/internal/audit"
)

func main() {
	inPath := flag.String("in", "", "input JSON file describing the zone")
	outPath := flag.String("out", "", "path to write the JSON report")
	flag.Parse()

	if *inPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: zonecheck -in records.json -out report.json")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read input: %v\n", err)
		os.Exit(2)
	}

	var in audit.Input
	if err := json.Unmarshal(raw, &in); err != nil {
		fatalReport(*outPath, audit.Report{
			Problems:  []audit.Problem{{Code: "invalid_json", Message: err.Error()}},
			CNAMEs:    []audit.CNAMEResult{},
			MXResults: []audit.MXResult{},
		})
	}

	rep := audit.Run(in)
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot encode report: %v\n", err)
		os.Exit(2)
	}
	if err := os.WriteFile(*outPath, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write report: %v\n", err)
		os.Exit(2)
	}

	if !rep.OK {
		os.Exit(1)
	}
}

// fatalReport writes a minimal diagnostic report and exits non-zero.
func fatalReport(path string, rep audit.Report) {
	rep.OK = false
	data, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write report: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "input rejected: %s\n", rep.Problems[0].Message)
	os.Exit(1)
}
