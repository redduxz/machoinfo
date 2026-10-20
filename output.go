package main

import (
	"fmt"
	"sort"
	"strings"
)

func printReport(r *Report) {
	fmt.Printf("%s  (%s, %s)\n", r.Path, humanSize(r.Size), r.FileMode)
	fmt.Printf("  type:    %s %s\n", r.FileType, strings.Join(r.Archs, ","))
	if len(r.Flags) > 0 {
		fmt.Printf("  flags:   %s\n", strings.Join(r.Flags, " "))
	}
	if r.MinOS != "" {
		fmt.Printf("  min os:  %s\n", r.MinOS)
	}
	if r.UUID != "" {
		fmt.Printf("  uuid:    %s\n", r.UUID)
	}

	// signature block
	if r.Signature != nil {
		s := r.Signature
		fmt.Printf("  sign:    %s", s.Status)
		var bits []string
		if s.Runtime {
			bits = append(bits, "hardened")
		}
		if s.Notarized {
			bits = append(bits, "notarized")
		}
		if len(bits) > 0 {
			fmt.Printf(" (%s)", strings.Join(bits, ", "))
		}
		fmt.Println()
		if s.Identifier != "" {
			fmt.Printf("  ident:   %s\n", s.Identifier)
		}
		if s.TeamID != "" {
			fmt.Printf("  team:    %s\n", s.TeamID)
		}
		if len(s.CDFlags) > 0 {
			fmt.Printf("  cdflags: %s\n", strings.Join(s.CDFlags, " "))
		}
	}

	// entitlements
	if len(r.Entitlements) > 0 {
		fmt.Printf("  entitlements (%d):\n", len(r.Entitlements))
		keys := make([]string, 0, len(r.Entitlements))
		for k := range r.Entitlements {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("    %s = %s\n", k, r.Entitlements[k])
		}
	}

	if r.InstallName != "" {
		fmt.Printf("  install: %s\n", r.InstallName)
	}
	if len(r.Rpaths) > 0 {
		fmt.Printf("  rpaths:\n")
		for _, rp := range r.Rpaths {
			fmt.Printf("    %s\n", rp)
		}
	}
	if len(r.Dylibs) > 0 {
		fmt.Printf("  dylibs (%d):\n", len(r.Dylibs))
		for _, d := range r.Dylibs {
			fmt.Printf("    %s\n", d)
		}
	}

	// segments/sections
	for _, seg := range r.Segments {
		fmt.Printf("  %s  vm=%#x size=%s prot=%s\n",
			seg.Name, seg.VMAddr, humanSize(int64(seg.Size)), seg.Prot)
		for _, s := range seg.Sections {
			fmt.Printf("      %-16s %10s  e=%.2f\n", s.Name, humanSize(int64(s.Size)), s.Entropy)
		}
	}

	if len(r.Imports) > 0 {
		fmt.Printf("  imports: %d  exports: %d\n", len(r.Imports), len(r.Exports))
		n := len(r.Imports)
		if n > 25 {
			n = 25
		}
		for _, im := range r.Imports[:n] {
			fmt.Printf("    %s\n", im)
		}
		if len(r.Imports) > n {
			fmt.Printf("    … %d more\n", len(r.Imports)-n)
		}
	}

	printSummaryLine(r)
	if len(r.Findings) > 0 {
		fmt.Printf("  findings:\n")
		for _, f := range r.Findings {
			fmt.Printf("    ⚑ %s\n", f)
		}
	}
}

// printSummaryLine is the one-line posture summary (used in both modes).
func printSummaryLine(r *Report) {
	sig := "unsigned"
	if r.Signature != nil {
		sig = r.Signature.Status
		if r.Signature.Runtime {
			sig += "+rt"
		}
		if r.Signature.Notarized {
			sig += "+notar"
		}
	}
	fmt.Printf("  %s | %s | %d entitlements | %d findings\n",
		strings.Join(r.Archs, ","), sig, len(r.Entitlements), len(r.Findings))
}

func humanSize(n int64) string {
	for _, u := range []string{"B", "K", "M", "G"} {
		if n < 1024 {
			return fmt.Sprintf("%d%s", n, u)
		}
		n /= 1024
	}
	return fmt.Sprintf("%dT", n)
}
