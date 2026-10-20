package main

import (
	"fmt"
	"strings"
)

// entitlements that materially weaken the security posture of a binary.
var riskyEntitlements = map[string]string{
	"com.apple.security.get-task-allow":                        "debugger attach permitted",
	"com.apple.security.cs.allow-dyld-environment-variables":   "DYLD_* env vars honored - injection surface",
	"com.apple.security.cs.disable-library-validation":         "library validation off - unsigned dylibs load",
	"com.apple.security.cs.disable-executable-page-protection": "W^X disabled - RWX memory allowed",
	"com.apple.security.cs.allow-unsigned-executable-memory":   "unsigned executable memory allowed",
	"com.apple.security.cs.allow-jit":                          "JIT pages allowed",
	"com.apple.private.security.no-sandbox":                    "private entitlement: no-sandbox",
	"com.apple.private.persona-mgmt":                           "private entitlement",
	"com.apple.private.tcc.manager":                            "private entitlement: TCC manager",
	"com.apple.rootless.install":                               "rootless install entitlement",
	"com.apple.developer.kernel.extended-virtual-addressing":   "kernel VA extension",
	"task_for_pid-allow":                                       "task_for_pid allowed",
}

// deriveFindings runs the rules engine over a parsed report.
func deriveFindings(r *Report) []string {
	var out []string

	if r.Setuid {
		out = append(out, "setuid bit set")
	}
	if r.Setgid {
		out = append(out, "setgid bit set")
	}

	if r.Encrypted {
		out = append(out, "FairPlay-encrypted sections (cryptid set) - static analysis limited")
	}

	// signature posture
	if r.Signature == nil || r.Signature.Status == "none" {
		out = append(out, "unsigned binary")
	} else {
		s := r.Signature
		if s.Status == "adhoc" {
			out = append(out, "ad-hoc signed - no developer identity")
		}
		// hardened runtime only matters for third-party (notarized) binaries;
		// Apple platform binaries are exempt by design
		if s.Status == "signed" && !s.Runtime && !strings.HasPrefix(s.Identifier, "com.apple.") {
			out = append(out, "signed without hardened runtime")
		}
	}

	// entitlements
	for k, why := range riskyEntitlements {
		if _, ok := r.Entitlements[k]; ok {
			out = append(out, why+" ["+k+"]")
		}
	}
	for k := range r.Entitlements {
		if strings.HasPrefix(k, "com.apple.private.") {
			if _, flagged := riskyEntitlements[k]; !flagged {
				out = append(out, "private entitlement: "+k)
			}
		}
	}

	// rpath hygiene
	var badRpaths, hasRelative bool
	for _, rp := range r.Rpaths {
		if !strings.HasPrefix(rp, "/") && !strings.HasPrefix(rp, "@") {
			hasRelative = true
		}
		if strings.Contains(rp, "/tmp") || strings.Contains(rp, "$HOME") ||
			strings.Contains(rp, "~/") || strings.Contains(rp, "/Users/") {
			badRpaths = true
		}
	}
	if hasRelative {
		out = append(out, "relative LC_RPATH entries - dylib search-path risk")
	}
	if badRpaths {
		out = append(out, "LC_RPATH points into user-writable location - dylib hijack surface")
	}
	if len(r.Rpaths) > 0 {
		for _, d := range r.Dylibs {
			if strings.HasPrefix(d, "@rpath") {
				out = append(out, "loads @rpath dylibs - verify rpath dirs are protected")
				break
			}
		}
	}
	for _, d := range r.WeakDylibs {
		if strings.HasPrefix(d, "@rpath") || strings.HasPrefix(d, "@executable_path") {
			out = append(out, "weak dylib "+d+" - missing file tolerated, hijack primitive")
		}
	}

	// packed-looking sections (skip DWARF debug sections - compressed, not packed)
	for _, seg := range r.Segments {
		for _, s := range seg.Sections {
			if strings.HasPrefix(s.Name, "__zdebug") || strings.HasPrefix(s.Name, "__debug") {
				continue
			}
			if s.Entropy >= 7.2 && s.Size > 4096 {
				out = append(out, "high-entropy section "+s.Name+" ("+
					f2s(s.Entropy)+") - packed/encrypted-looking")
			}
		}
	}

	return out
}

func f2s(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		fmt.Sprintf("%.2f", f), "0"), ".")
}
