package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// ANSI styling — disabled when stdout isn't a TTY or NO_COLOR is set.
var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") != "" {
		return true
	}
	st, _ := os.Stdout.Stat()
	return st != nil && st.Mode()&os.ModeCharDevice != 0
}()

func paint(c, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + c + "m" + s + "\x1b[0m"
}

var (
	bold   = func(s string) string { return paint("1", s) }
	dim    = func(s string) string { return paint("2", s) }
	cyan   = func(s string) string { return paint("36", s) }
	green  = func(s string) string { return paint("32", s) }
	red    = func(s string) string { return paint("31", s) }
	yellow = func(s string) string { return paint("33", s) }
	mag    = func(s string) string { return paint("35", s) }
)

func sev(f string) string {
	// red for the dangerous class, yellow for hygiene
	low := strings.ToLower(f)
	for _, k := range []string{"unsigned binary", "setuid", "setgid", "hijack",
		"no developer", "env vars", "library validation", "w^x", "unsigned executable"} {
		if strings.Contains(low, k) {
			return red("⚑ ") + red(f)
		}
	}
	return yellow("⚑ ") + f
}

func rule() string { return dim(strings.Repeat("─", 60)) }

func printReport(r *Report) {
	// ─── header ───
	name := r.Path
	fmt.Printf("%s\n", rule())
	fmt.Printf(" %s  %s\n", bold(name), dim(humanSize(r.Size)+" · "+r.FileMode))

	meta := []string{r.FileType, strings.Join(r.Archs, ", ")}
	if len(r.Flags) > 0 {
		meta = append(meta, strings.Join(r.Flags, " "))
	}
	fmt.Printf("  %s\n", dim(strings.Join(meta, " · ")))
	if r.MinOS != "" {
		plat := ""
		if r.Platform != "" {
			plat = " (" + r.Platform + ")"
		}
		fmt.Printf("  %s %s%s\n", dim("min os"), r.MinOS, dim(plat))
	}
	if r.UUID != "" {
		fmt.Printf("  %s %s\n", dim("uuid  "), r.UUID)
	}
	if r.Encrypted {
		fmt.Printf("  %s\n", red("!! FairPlay-encrypted — static analysis limited"))
	}
	fmt.Println()

	// ─── signature ───
	fmt.Printf(" %s\n", cyan(bold("SIGNATURE")))
	if r.Signature == nil || r.Signature.Status == "none" {
		fmt.Printf("   %s\n", red("✗ unsigned"))
	} else {
		s := r.Signature
		var badge string
		switch s.Status {
		case "signed":
			badge = green("✓ signed")
		case "adhoc":
			badge = yellow("~ ad-hoc")
		default:
			badge = dim(s.Status)
		}
		var tags []string
		if s.Runtime {
			tags = append(tags, green("hardened-runtime"))
		}
		if s.Notarized {
			tags = append(tags, green("notarized"))
		}
		fmt.Printf("   %s %s\n", badge, strings.Join(tags, "  "))
		if s.Identifier != "" {
			fmt.Printf("   %s %s\n", dim("ident "), s.Identifier)
		}
		if s.TeamID != "" {
			fmt.Printf("   %s %s\n", dim("team  "), s.TeamID)
		}
		if len(s.CDFlags) > 0 {
			fmt.Printf("   %s %s\n", dim("flags "), strings.Join(s.CDFlags, " "))
		}
	}

	// ─── entitlements ───
	if len(r.Entitlements) > 0 {
		fmt.Printf("\n %s\n", cyan(bold(fmt.Sprintf("ENTITLEMENTS  %d", len(r.Entitlements)))))
		keys := make([]string, 0, len(r.Entitlements))
		for k := range r.Entitlements {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, risky := riskyEntitlements[k]
			priv := strings.HasPrefix(k, "com.apple.private.")
			kd := k
			if risky {
				kd = red(k)
			} else if priv {
				kd = yellow(k)
			}
			fmt.Printf("   %s %s %s\n", dim(kd), dim("="), r.Entitlements[k])
		}
	}

	// ─── linkage ───
	if r.InstallName != "" {
		fmt.Printf("  %s %s\n", dim("install"), r.InstallName)
	}
	if len(r.Dylibs) > 0 || len(r.Rpaths) > 0 {
		fmt.Printf("\n %s\n", cyan(bold(fmt.Sprintf("LINKAGE  %d dylibs · %d rpaths", len(r.Dylibs), len(r.Rpaths)))))
		for _, d := range r.Dylibs {
			fmt.Printf("   %s %s\n", dim("lib  "), d)
		}
		for _, rp := range r.Rpaths {
			bad := strings.Contains(rp, "/tmp") || strings.Contains(rp, "/Users/") || strings.Contains(rp, "~/")
			if bad {
				fmt.Printf("   %s %s\n", red("rpath"), red(rp))
			} else {
				fmt.Printf("   %s %s\n", dim("rpath"), rp)
			}
		}
		for _, d := range r.WeakDylibs {
			fmt.Printf("   %s %s\n", yellow("weak "), yellow(d))
		}
	}

	// ─── segments ───
	if len(r.Segments) > 0 {
		fmt.Printf("\n %s\n", cyan(bold("SEGMENTS")))
		for _, seg := range r.Segments {
			fmt.Printf("   %-12s %s %8s %s\n",
				bold(seg.Name), dim(fmt.Sprintf("vm %#x", seg.VMAddr)),
				humanSize(int64(seg.Size)), mag(seg.Prot))
			for _, s := range seg.Sections {
				ent := fmt.Sprintf("e=%.2f", s.Entropy)
				if s.Entropy >= 7.2 && s.Size > 4096 {
					ent = red(ent)
				} else {
					ent = dim(ent)
				}
				fmt.Printf("      %-18s %10s  %s\n",
					s.Name, humanSize(int64(s.Size)), ent)
			}
		}
	}

	// ─── imports ───
	if len(r.Imports) > 0 {
		fmt.Printf("\n %s\n", cyan(bold(fmt.Sprintf("SYMBOLS  %d imports · %d exports", len(r.Imports), len(r.Exports)))))
		n := len(r.Imports)
		if n > 12 {
			n = 12
		}
		for _, im := range r.Imports[:n] {
			fmt.Printf("   %s\n", dim(im))
		}
		if len(r.Imports) > n {
			fmt.Printf("   %s\n", dim(fmt.Sprintf("… %d more", len(r.Imports)-n)))
		}
	}

	// ─── strings ───
	if len(r.Strings) > 0 {
		fmt.Printf("\n %s\n", cyan(bold(fmt.Sprintf("STRINGS  %d interesting", len(r.Strings)))))
		for _, s := range r.Strings {
			fmt.Printf("   %s\n", dim(s))
		}
	}

	// ─── verdict ───
	fmt.Printf("\n %s\n", cyan(bold("FINDINGS")))
	if len(r.Findings) == 0 {
		fmt.Printf("   %s\n", green("✓ clean"))
	} else {
		for _, f := range r.Findings {
			fmt.Printf("   %s\n", sev(f))
		}
	}
	fmt.Printf("%s\n", rule())
}

// printSummaryLine is the one-line posture summary (scan mode).
func printSummaryLine(r *Report) {
	sig := red("unsigned")
	if r.Signature != nil {
		switch r.Signature.Status {
		case "signed":
			sig = green("signed")
		case "adhoc":
			sig = yellow("adhoc")
		default:
			sig = dim(r.Signature.Status)
		}
		if r.Signature.Runtime {
			sig += green("+rt")
		}
		if r.Signature.Notarized {
			sig += green("+notar")
		}
	}
	fmt.Printf("  %s  %s  %s  %s\n",
		dim(strings.Join(r.Archs, ",")), sig,
		dim(fmt.Sprintf("%d ents", len(r.Entitlements))),
		findingBadge(len(r.Findings)))
}

func findingBadge(n int) string {
	if n == 0 {
		return green("✓")
	}
	return yellow(fmt.Sprintf("%d ⚑", n))
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
