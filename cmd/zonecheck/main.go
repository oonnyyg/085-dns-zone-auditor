// Command zonecheck validates a DNS zone description read from JSON and
// writes a JSON diagnostic report. It never sends DNS queries.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/dns-zone-auditor/zone"
)

func main() {
	inPath := flag.String("in", "", "path to input JSON file (zone name and records)")
	outPath := flag.String("out", "", "path to write the JSON report")
	flag.Parse()
	if *inPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: zonecheck -in input.json -out report.json")
		os.Exit(2)
	}
	data, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zonecheck: %v\n", err)
		os.Exit(2)
	}
	input, err := zone.ParseInput(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zonecheck: %v\n", err)
		os.Exit(2)
	}
	z, problems := zone.Build(input)
	var report *zone.Report
	if z == nil {
		report = &zone.Report{OK: false, Problems: problems, CNAMEs: []zone.CNAMEResult{}, MX: []zone.MXResult{}}
	} else {
		report = z.Analyze(problems, zone.ConflictedNodes(problems))
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "zonecheck: %v\n", err)
		os.Exit(2)
	}
	out = append(out, '\n')
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "zonecheck: %v\n", err)
		os.Exit(2)
	}
	if !report.OK {
		fmt.Fprintf(os.Stderr, "zonecheck: problems found, report written to %s\n", *outPath)
		os.Exit(1)
	}
	fmt.Printf("zonecheck: ok, report written to %s\n", *outPath)
}
