package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

var inShell bool

var shellCommands = []string{
	"open", "scan", "procs", "diff", "findings", "sign", "ents",
	"dylibs", "rpaths", "sections", "strings", "imports", "header",
	"json", "info", "clear", "help", "exit",
}

const helpText = `commands:
  open <file>      analyze a binary (loads it for drilldown)
  scan [dir]       audit a directory (defaults to .)
  procs            audit running processes
  diff <a> <b>     compare two binaries (quote paths with spaces)

drilldown (on the loaded binary):
  findings  sign  ents  dylibs  rpaths  sections  strings  imports  header  json

  clear            clear screen          exit      leave (ctrl-d)
  tab completes commands and paths
`

// runShell is the interactive REPL.
func runShell() {
	inShell = true
	animatedBanner()
	fmt.Println(dim("  type " + "help" + " for commands · tab completes · ctrl-d exits"))
	fmt.Println()

	var hist []string
	var cur *Report

	prompt := func() string {
		if cur != nil {
			return cyan("machoinfo") + dim(" ["+shortName(cur.Path)+"]") + cyan("⟩ ")
		}
		return cyan("machoinfo") + cyan("⟩ ")
	}

	for {
		line, ok := readLine(prompt(), &hist, completer)
		if !ok {
			fmt.Println(dim("bye"))
			return
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		hist = append(hist, line)
		trimmed := strings.TrimSpace(line)
		rest := strings.TrimSpace(trimmed[len(f[0]):]) // args, spaces preserved

		switch strings.ToLower(f[0]) {
		case "exit", "quit", "q":
			fmt.Println(dim("bye"))
			return
		case "help", "h", "?":
			fmt.Print(helpText)
		case "clear", "cls":
			fmt.Fprint(os.Stderr, "\x1b[2J\x1b[H")
		case "open", "file", "o", "load":
			if rest == "" {
				fmt.Println(dim("usage: open <file>"))
				break
			}
			cur = cmdOpen(expandTilde(unquote(rest)))
		case "scan", "s":
			dir := "."
			if rest != "" {
				dir = expandTilde(unquote(rest))
			}
			runScan(dir)
		case "procs":
			runProcs()
		case "diff":
			parts := splitArgs(rest)
			if len(parts) != 2 {
				fmt.Println(dim("usage: diff <old> <new>  (quote paths with spaces)"))
				break
			}
			a, err := Analyze(expandTilde(parts[0]))
			if err != nil {
				fmt.Println(red(err.Error()))
				break
			}
			b, err := Analyze(expandTilde(parts[1]))
			if err != nil {
				fmt.Println(red(err.Error()))
				break
			}
			printDiff(DiffReports(a, b))
		case "findings", "f":
			drill(cur, func(r *Report) {
				if len(r.Findings) == 0 {
					fmt.Println(green("  ✓ clean"))
					return
				}
				for _, x := range r.Findings {
					fmt.Println("  " + sev(x))
				}
			})
		case "sign", "sig":
			drill(cur, printSigDetail)
		case "ents", "entitlements":
			drill(cur, printEnts)
		case "dylibs", "libs":
			drill(cur, func(r *Report) {
				for _, d := range r.Dylibs {
					fmt.Println("  " + d)
				}
				for _, d := range r.WeakDylibs {
					fmt.Println("  " + yellow("weak "+d))
				}
			})
		case "rpaths":
			drill(cur, func(r *Report) {
				for _, rp := range r.Rpaths {
					fmt.Println("  " + rp)
				}
			})
		case "sections", "seg":
			drill(cur, printSections)
		case "strings":
			drill(cur, func(r *Report) {
				for _, s := range r.Strings {
					fmt.Println("  " + s)
				}
			})
		case "imports":
			drill(cur, func(r *Report) {
				for _, s := range r.Imports {
					fmt.Println("  " + s)
				}
			})
		case "header", "hdr":
			drill(cur, printHeader)
		case "json":
			drill(cur, func(r *Report) { emitJSON(r) })
		case "info":
			drill(cur, func(r *Report) { printReport(r) })
		default:
			fmt.Println(dim("  unknown command - 'help'"))
		}
	}
}

func cmdOpen(path string) *Report {
	sp := startSpinner(func() string { return "triaging " + path })
	r, err := Analyze(path)
	sp.stop()
	if err != nil {
		fmt.Println(red("  " + err.Error()))
		return nil
	}
	printCard(r)
	return r
}

// printCard is the compact post-open summary (not the full report).
func printCard(r *Report) {
	fmt.Printf(" %s\n", bold(r.Path))
	fmt.Printf("  %s\n", dim(strings.Join([]string{
		r.FileType, strings.Join(r.Archs, ", "), humanSize(r.Size),
	}, " · ")))
	printSummaryLine(r)
	fmt.Println(dim("  drilldown: findings · ents · sections · dylibs · strings · json"))
}

func drill(cur *Report, fn func(*Report)) {
	if cur == nil {
		fmt.Println(dim("  nothing loaded - 'open <file>' first"))
		return
	}
	fn(cur)
}

func printSigDetail(r *Report) {
	s := r.Signature
	if s == nil || s.Status == "none" {
		fmt.Println("  " + red("✗ unsigned"))
		return
	}
	fmt.Printf("  status    %s\n", s.Status)
	if s.Identifier != "" {
		fmt.Printf("  ident     %s\n", s.Identifier)
	}
	if s.TeamID != "" {
		fmt.Printf("  team      %s\n", s.TeamID)
	}
	fmt.Printf("  hardened  %v   notarized  %v   cms  %v\n", s.Runtime, s.Notarized, s.HasCMS)
	if len(s.CDFlags) > 0 {
		fmt.Printf("  cdflags   %s\n", strings.Join(s.CDFlags, " "))
	}
}

func printEnts(r *Report) {
	if len(r.Entitlements) == 0 {
		fmt.Println(dim("  none"))
		return
	}
	keys := make([]string, 0, len(r.Entitlements))
	for k := range r.Entitlements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		mark := "  "
		if _, risky := riskyEntitlements[k]; risky {
			mark = red("! ")
		} else if strings.HasPrefix(k, "com.apple.private.") {
			mark = yellow("? ")
		}
		fmt.Printf("%s%s = %s\n", mark, k, r.Entitlements[k])
	}
}

func printSections(r *Report) {
	for _, seg := range r.Segments {
		fmt.Printf("  %-12s %-10s %s\n", seg.Name, humanSize(int64(seg.Size)), seg.Prot)
		for _, s := range seg.Sections {
			fmt.Printf("      %-18s %8s  e=%.2f\n", s.Name, humanSize(int64(s.Size)), s.Entropy)
		}
	}
}

func printHeader(r *Report) {
	fmt.Printf("  type     %s %s\n", r.FileType, strings.Join(r.Archs, ","))
	if r.MinOS != "" {
		plat := ""
		if r.Platform != "" {
			plat = " (" + r.Platform + ")"
		}
		fmt.Printf("  min os   %s%s\n", r.MinOS, plat)
	}
	fmt.Printf("  size     %s\n", humanSize(r.Size))
	fmt.Printf("  mode     %s\n", r.FileMode)
	if r.UUID != "" {
		fmt.Printf("  uuid     %s\n", r.UUID)
	}
	fmt.Printf("  flags    %s\n", strings.Join(r.Flags, " "))
	fmt.Printf("  fat      %v   encrypted  %v\n", r.Fat, r.Encrypted)
}

func shortName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func expandTilde(p string) string {
	if p == "~" {
		h, _ := os.UserHomeDir()
		return h
	}
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return h + p[1:]
	}
	return p
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ' ' && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// completer: first word = commands; args = file paths.
func completer(word string, first bool) []string {
	if first {
		var out []string
		for _, c := range shellCommands {
			if strings.HasPrefix(c, word) {
				out = append(out, c)
			}
		}
		return out
	}
	return pathCompletions(word)
}

func pathCompletions(word string) []string {
	// find dir portion; keep the typed prefix for results
	dir := word
	base := ""
	if i := strings.LastIndex(word, "/"); i >= 0 {
		dir, base = word[:i+1], word[i+1:]
	} else {
		dir = ""
	}
	realDir := dir
	if realDir == "" {
		realDir = "."
	}
	realDir = expandTilde(realDir)
	ents, err := os.ReadDir(realDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), base) {
			continue
		}
		c := dir + e.Name()
		if e.IsDir() {
			c += "/"
		}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// animatedBanner: magic bytes slot-settle left-to-right onto fe ed fa cf,
// then the tagline types out. ~0.6s total.
func animatedBanner() {
	top := "╭─────────────╮"
	bot := "╰─────────────╯"
	realBytes := "fe ed fa cf"
	tag := "mach-o triage · peinfo for macos"

	if !useColor {
		fmt.Printf("%s\n│ %s │  machoinfo\n%s  %s\n\n", top, realBytes, bot, tag)
		return
	}

	fmt.Println(dim(top))
	hex := "0123456789abcdef"
	slot := func(from int) string {
		var b strings.Builder
		for i := from; i < 11; i++ {
			if i%3 == 2 {
				b.WriteByte(' ')
			} else {
				b.WriteByte(hex[rand.Intn(16)])
			}
		}
		return b.String()
	}

	locked := 0
	delay := 22 * time.Millisecond
	for locked < 11 {
		line := realBytes[:locked] + slot(locked)
		fmt.Fprintf(os.Stderr, "\r%s%s%s  %s", dim("│"), cyan(" "+line+" "), dim("│"), bold("machoinfo"))
		time.Sleep(delay)
		locked++
		delay += 5 * time.Millisecond // decelerate like a reel
	}
	fmt.Fprintf(os.Stderr, "\r%s%s%s  %s\n", dim("│"), cyan(" "+realBytes+" "), dim("│"), bold("machoinfo"))
	fmt.Fprintf(os.Stderr, "%s  ", dim(bot))
	for _, ch := range tag {
		fmt.Fprintf(os.Stderr, "%s", dim(string(ch)))
		time.Sleep(7 * time.Millisecond)
	}
	fmt.Println()
	fmt.Println()
}
