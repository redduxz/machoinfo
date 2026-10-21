package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

const helpText = `commands:
  open <file>      analyze a binary (loads it for drilldown)
  scan <dir>       audit a directory - flagged binaries only
  procs            audit running processes
  diff <a> <b>     compare two binaries
  drilldown on loaded binary:
    findings   verdict findings          sign      signature details
    ents       entitlements              dylibs    linked libraries
    sections   segments + entropy        rpaths    runpath entries
    strings    interesting strings       imports   imported symbols
    header     headers / uuid / minos    json      full JSON report
  clear            clear screen          exit      leave (ctrl-d works too)
`

// runShell is the interactive REPL.
func runShell() {
	animatedBanner()
	fmt.Println(dim("  type " + "help" + " for commands · ctrl-d to exit"))
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
		line, ok := readLine(prompt(), &hist)
		if !ok {
			fmt.Println(dim("bye"))
			return
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		hist = append(hist, line)

		switch strings.ToLower(f[0]) {
		case "exit", "quit", "q":
			fmt.Println(dim("bye"))
			return
		case "help", "h", "?":
			fmt.Print(helpText)
		case "clear", "cls":
			fmt.Fprint(os.Stderr, "\x1b[2J\x1b[H")
		case "open", "file", "o", "load":
			if len(f) < 2 {
				fmt.Println(dim("usage: open <file>"))
				break
			}
			cur = cmdOpen(f[1])
		case "scan", "s":
			if len(f) < 2 {
				fmt.Println(dim("usage: scan <dir>"))
				break
			}
			runScan(f[1])
		case "procs":
			runProcs()
		case "diff":
			if len(f) != 3 {
				fmt.Println(dim("usage: diff <old> <new>"))
				break
			}
			a, err := Analyze(f[1])
			if err != nil {
				fmt.Println(red(err.Error()))
				break
			}
			b, err := Analyze(f[2])
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

// animatedBanner: the magic bytes settle like a slot machine, then lock on fe ed fa cf.
func animatedBanner() {
	top := "╭─────────────╮"
	bot := "╰─────────────╯"
	realBytes := "fe ed fa cf"

	if !useColor {
		fmt.Printf("%s\n│ %s │  machoinfo\n%s  mach-o triage - peinfo for macos\n\n",
			top, realBytes, bot)
		return
	}

	fmt.Println(dim(top))
	hex := "0123456789abcdef"
	slot := func() string {
		var b strings.Builder
		for i := 0; i < 11; i++ {
			if i%3 == 2 {
				b.WriteByte(' ')
				continue
			}
			b.WriteByte(hex[rand.Intn(16)])
		}
		return b.String()
	}

	// settle: each position locks left-to-right
	locked := 0
	for frame := 0; frame < 14; frame++ {
		line := realBytes[:locked] + slot()[:11-locked]
		fmt.Fprintf(os.Stderr, "\r%s%s%s  %s", dim("│"), cyan(" "+line+" "), dim("│"), bold("machoinfo"))
		time.Sleep(45 * time.Millisecond)
		if frame%2 == 1 && locked < 11 {
			locked++
		}
	}
	fmt.Fprintf(os.Stderr, "\r%s%s%s  %s\n", dim("│"), cyan(" "+realBytes+" "), dim("│"), bold("machoinfo"))
	fmt.Printf("%s  %s\n\n", dim(bot), dim("mach-o triage · peinfo for macos"))
}
