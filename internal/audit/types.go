package audit

// InputRecord is a single record as supplied in the input JSON.
type InputRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl"`
	// Data holds the rdata: an IPv4 address for A, a target domain for
	// CNAME, and "priority host" for MX.
	Data string `json:"data"`
}

// Input is the zone description read by the tool.
type Input struct {
	Zone    string        `json:"zone"`
	Records []InputRecord `json:"records"`
}

// Problem is a single validation or semantic issue.
type Problem struct {
	Code    string `json:"code"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	Message string `json:"message"`
}

// CNAMEResult describes a CNAME owner: its full alias chain and terminal.
type CNAMEResult struct {
	Name   string   `json:"name"`
	Target string   `json:"target"`
	Path   []string `json:"path"`
	// Status is one of:
	// resolved, no_address, dangling, conflict, loop, external_unknown.
	Status    string   `json:"status"`
	Addresses []string `json:"addresses,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// MXResult describes one validated MX target.
type MXResult struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Target   string `json:"target"`
	// Status is one of: resolved, external_unverified, missing, alias.
	Status    string   `json:"status,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// Report is the JSON document written to the output file.
type Report struct {
	Zone      string        `json:"zone"`
	OK        bool          `json:"ok"`
	Problems  []Problem     `json:"problems"`
	CNAMEs    []CNAMEResult `json:"cnames"`
	MXResults []MXResult    `json:"mx"`
}
