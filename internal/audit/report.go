package audit

import "sort"

// finalize orders problems deterministically and computes the OK flag.
// Conclusions never depend on input order: sorting is by name/code with
// stable ties.
func finalize(rep *Report) {
	if rep.Problems == nil {
		rep.Problems = []Problem{}
	}
	sort.SliceStable(rep.Problems, func(i, j int) bool {
		a, b := rep.Problems[i], rep.Problems[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Code < b.Code
	})
	rep.OK = len(rep.Problems) == 0
}
