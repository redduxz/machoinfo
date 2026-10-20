package main

import (
	"fmt"
	"sort"
)

// Diff holds the deltas between two triaged binaries.
type Diff struct {
	A             string            `json:"a"`
	B             string            `json:"b"`
	AddedDylibs   []string          `json:"added_dylibs,omitempty"`
	RemovedLibs   []string          `json:"removed_dylibs,omitempty"`
	AddedRpath    []string          `json:"added_rpaths,omitempty"`
	RemovedRpath  []string          `json:"removed_rpaths,omitempty"`
	EntAdded      map[string]string `json:"entitlements_added,omitempty"`
	EntRemoved    map[string]string `json:"entitlements_removed,omitempty"`
	EntChanged    map[string]string `json:"entitlements_changed,omitempty"`
	SigChange     string            `json:"signature_change,omitempty"`
	SizeDelta     int64             `json:"size_delta"`
	ArchChange    string            `json:"arch_change,omitempty"`
	NewFindings   []string          `json:"new_findings,omitempty"`
	FixedFindings []string          `json:"fixed_findings,omitempty"`
	SectionsAdded []string          `json:"sections_added,omitempty"`
	SectionsGone  []string          `json:"sections_removed,omitempty"`
}

// DiffReports compares two reports and returns the delta (a → b).
func DiffReports(a, b *Report) *Diff {
	d := &Diff{A: a.Path, B: b.Path, SizeDelta: b.Size - a.Size}

	d.AddedDylibs, d.RemovedLibs = listDiff(a.Dylibs, b.Dylibs)
	d.AddedRpath, d.RemovedRpath = listDiff(a.Rpaths, b.Rpaths)
	d.EntAdded, d.EntRemoved, d.EntChanged = mapDiff(a.Entitlements, b.Entitlements)
	d.SectionsAdded, d.SectionsGone = listDiff(sectionNames(a), sectionNames(b))
	d.NewFindings, d.FixedFindings = listDiff(a.Findings, b.Findings)

	as, bs := sigSummary(a), sigSummary(b)
	if as != bs {
		d.SigChange = as + " → " + bs
	}
	aa, ba := joinSet(a.Archs), joinSet(b.Archs)
	if aa != ba {
		d.ArchChange = aa + " → " + ba
	}
	return d
}

func sigSummary(r *Report) string {
	if r.Signature == nil {
		return "unsigned"
	}
	s := r.Signature.Status
	if r.Signature.Runtime {
		s += "+rt"
	}
	if r.Signature.Notarized {
		s += "+notar"
	}
	return s
}

func sectionNames(r *Report) []string {
	var out []string
	for _, seg := range r.Segments {
		for _, s := range seg.Sections {
			out = append(out, seg.Name+"/"+s.Name)
		}
	}
	return out
}

func listDiff(a, b []string) (added, removed []string) {
	as, bs := toSet(a), toSet(b)
	for k := range bs {
		if !as[k] {
			added = append(added, k)
		}
	}
	for k := range as {
		if !bs[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func mapDiff(a, b map[string]string) (added, removed, changed map[string]string) {
	for k, bv := range b {
		if av, ok := a[k]; !ok {
			if added == nil {
				added = map[string]string{}
			}
			added[k] = bv
		} else if av != bv {
			if changed == nil {
				changed = map[string]string{}
			}
			changed[k] = av + " → " + bv
		}
	}
	for k, av := range a {
		if _, ok := b[k]; !ok {
			if removed == nil {
				removed = map[string]string{}
			}
			removed[k] = av
		}
	}
	return
}

func toSet(l []string) map[string]bool {
	m := make(map[string]bool, len(l))
	for _, x := range l {
		m[x] = true
	}
	return m
}

func joinSet(l []string) string {
	s := append([]string{}, l...)
	sort.Strings(s)
	return fmt.Sprintf("%v", s)
}

func printDiff(d *Diff) {
	fmt.Printf("diff: %s → %s  (size %+d)\n", d.A, d.B, d.SizeDelta)
	if d.SigChange != "" {
		fmt.Printf("  signature: %s\n", d.SigChange)
	}
	if d.ArchChange != "" {
		fmt.Printf("  archs:     %s\n", d.ArchChange)
	}
	printList := func(label string, l []string) {
		if len(l) == 0 {
			return
		}
		fmt.Printf("  %s (%d):\n", label, len(l))
		for _, x := range l {
			fmt.Printf("    %s\n", x)
		}
	}
	printList("added dylibs", d.AddedDylibs)
	printList("removed dylibs", d.RemovedLibs)
	printList("added rpaths", d.AddedRpath)
	printList("removed rpaths", d.RemovedRpath)
	printList("added sections", d.SectionsAdded)
	printList("removed sections", d.SectionsGone)
	for label, m := range map[string]map[string]string{
		"entitlements added":   d.EntAdded,
		"entitlements removed": d.EntRemoved,
		"entitlements changed": d.EntChanged,
	} {
		if len(m) == 0 {
			continue
		}
		fmt.Printf("  %s (%d):\n", label, len(m))
		for k, v := range m {
			fmt.Printf("    %s = %s\n", k, v)
		}
	}
	printList("new findings", d.NewFindings)
	printList("resolved findings", d.FixedFindings)
}
