package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
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

  info             full report           clear     clear screen
  exit             leave (ctrl-d)        tab       completes commands + paths
`

// out prints a line; staggers slightly in the shell for a cascade feel.
func out(s string) {
	fmt.Println("  " + s)
	if useColor {
		time.Sleep(9 * time.Millisecond)
	}
}

// runShell is the interactive REPL.
func runShell() {
	inShell = true
	animatedBanner()

	var hist []string
	var cur *Report

	promptFn := func(alt bool) string {
		glyph := cyan("⟩ ")
		if alt {
			glyph = "\x1b[1;36m❯ \x1b[0m"
		}
		if cur != nil {
			badge := green(" ✓")
			if n := len(cur.Findings); n > 0 {
				badge = yellow(fmt.Sprintf(" ⚑%d", n))
			}
			return cyan("machoinfo") + dim(" ["+shortName(cur.Path)) + badge + dim("]") + glyph
		}
		return cyan("machoinfo") + glyph
	}

	for {
		line, ok := readLine(promptFn, &hist, completer)
		if !ok {
			fmt.Println(dim("bye"))
			return
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			fmt.Println(dim("  open <file> · scan [dir] · procs · diff <a> <b> · help"))
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
				out(dim("usage: open <file>"))
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
				out(dim("usage: diff <old> <new>  (quote paths with spaces)"))
				break
			}
			a, err := Analyze(expandTilde(parts[0]))
			if err != nil {
				out(red(err.Error()))
				break
			}
			b, err := Analyze(expandTilde(parts[1]))
			if err != nil {
				out(red(err.Error()))
				break
			}
			printDiff(DiffReports(a, b))
		case "findings", "f":
			drill(cur, "findings", func(r *Report) {
				if len(r.Findings) == 0 {
					out(green("✓ clean"))
					return
				}
				for _, x := range r.Findings {
					out(sev(x))
				}
			})
		case "sign", "sig":
			drill(cur, "signature", printSigDetail)
		case "ents", "entitlements":
			drill(cur, "entitlements", printEnts)
		case "dylibs", "libs":
			drill(cur, "dylibs", func(r *Report) {
				for _, d := range r.Dylibs {
					out(d)
				}
				for _, d := range r.WeakDylibs {
					out(yellow("weak " + d))
				}
			})
		case "rpaths":
			drill(cur, "rpaths", func(r *Report) {
				if len(r.Rpaths) == 0 {
					out(dim("none"))
				}
				for _, rp := range r.Rpaths {
					out(rp)
				}
			})
		case "sections", "seg":
			drill(cur, "sections", printSections)
		case "strings":
			drill(cur, "strings", func(r *Report) {
				if len(r.Strings) == 0 {
					out(dim("none"))
				}
				for _, s := range r.Strings {
					out(s)
				}
			})
		case "imports":
			drill(cur, "imports", func(r *Report) {
				for _, s := range r.Imports {
					out(s)
				}
			})
		case "header", "hdr":
			drill(cur, "header", printHeader)
		case "json":
			drill(cur, "json", func(r *Report) { emitJSON(r) })
		case "info":
			drill(cur, "report", func(r *Report) { printReport(r) })
		default:
			out(dim("unknown command - 'help'"))
		}
	}
}

func cmdOpen(path string) *Report {
	sp := startSpinner(func() string { return "triaging " + path })
	r, err := Analyze(path)
	sp.stop()
	if err != nil {
		out(red(err.Error()))
		return nil
	}
	printCard(r)
	return r
}

// printCard is the compact post-open summary (not the full report).
func printCard(r *Report) {
	out(bold(r.Path))
	out(dim(strings.Join([]string{
		r.FileType, strings.Join(r.Archs, ", "), humanSize(r.Size),
	}, " · ")))
	printSummaryLine(r)
	out(dim("drilldown: findings · ents · sections · dylibs · strings · json"))
}

// drill runs fn with a section header if a binary is loaded.
func drill(cur *Report, title string, fn func(*Report)) {
	if cur == nil {
		out(dim("nothing loaded - 'open <file>' first"))
		return
	}
	if title != "" {
		fmt.Println(" " + dim("▸ "+title))
	}
	fn(cur)
}

func printSigDetail(r *Report) {
	s := r.Signature
	if s == nil || s.Status == "none" {
		out(red("✗ unsigned"))
		return
	}
	out(fmt.Sprintf("status    %s", s.Status))
	if s.Identifier != "" {
		out(fmt.Sprintf("ident     %s", s.Identifier))
	}
	if s.TeamID != "" {
		out(fmt.Sprintf("team      %s", s.TeamID))
	}
	out(fmt.Sprintf("hardened  %v   notarized  %v   cms  %v", s.Runtime, s.Notarized, s.HasCMS))
	if len(s.CDFlags) > 0 {
		out(fmt.Sprintf("cdflags   %s", strings.Join(s.CDFlags, " ")))
	}
}

func printEnts(r *Report) {
	if len(r.Entitlements) == 0 {
		out(dim("none"))
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
		out(fmt.Sprintf("%s%s = %s", mark, k, r.Entitlements[k]))
	}
}

func printSections(r *Report) {
	for _, seg := range r.Segments {
		out(fmt.Sprintf("%-12s %-10s %s", seg.Name, humanSize(int64(seg.Size)), seg.Prot))
		for _, s := range seg.Sections {
			out(fmt.Sprintf("    %-18s %8s  e=%.2f", s.Name, humanSize(int64(s.Size)), s.Entropy))
		}
	}
}

func printHeader(r *Report) {
	out(fmt.Sprintf("type     %s %s", r.FileType, strings.Join(r.Archs, ",")))
	if r.MinOS != "" {
		plat := ""
		if r.Platform != "" {
			plat = " (" + r.Platform + ")"
		}
		out(fmt.Sprintf("min os   %s%s", r.MinOS, plat))
	}
	out(fmt.Sprintf("size     %s", humanSize(r.Size)))
	out(fmt.Sprintf("mode     %s", r.FileMode))
	if r.UUID != "" {
		out(fmt.Sprintf("uuid     %s", r.UUID))
	}
	out(fmt.Sprintf("flags    %s", strings.Join(r.Flags, " ")))
	out(fmt.Sprintf("fat      %v   encrypted  %v", r.Fat, r.Encrypted))
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

// animatedBanner: hex digits settle in scattered order (reel feel),
// snap to a cyan->violet gradient, tagline types out. ~0.7s.
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
	// hex-digit positions in "fe ed fa cf" (spaces pre-locked)
	order := []int{6, 0, 9, 3, 10, 4, 7, 1}
	locked := map[int]bool{2: true, 5: true, 8: true}
	renderMid := func() {
		var b strings.Builder
		for i := 0; i < 11; i++ {
			if locked[i] {
				b.WriteByte(realBytes[i])
			} else {
				b.WriteByte(hex[rand.Intn(16)])
			}
		}
		fmt.Fprintf(os.Stderr, "\r%s%s%s  %s", dim("│"), cyan(" "+b.String()+" "), dim("│"), bold("machoinfo"))
	}

	delay := 26 * time.Millisecond
	for _, idx := range order {
		renderMid()
		time.Sleep(delay)
		locked[idx] = true
		delay += 7 * time.Millisecond // decelerate
	}

	// final frame: gradient lockup
	c256 := func(n int, s string) string { return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", n, s) }
	fmt.Fprintf(os.Stderr, "\r%s %s %s %s %s %s  %s\n",
		dim("│"), c256(45, "fe"), c256(39, "ed"), c256(33, "fa"), c256(63, "cf"),
		dim("│"), bold("machoinfo"))
	fmt.Fprintf(os.Stderr, "%s  ", dim(bot))
	for _, ch := range tag {
		fmt.Fprintf(os.Stderr, "%s", dim(string(ch)))
		time.Sleep(6 * time.Millisecond)
	}
	fmt.Printf("\n%s\n\n", dim(fmt.Sprintf("  ready · %d cores · %s/%s · tab completes",
		runtime.NumCPU(), runtime.GOOS, runtime.GOARCH)))
}
