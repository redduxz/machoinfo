// machoinfo — rapid Mach-O triage: headers, entropy, dylibs, rpaths,
// code signing, entitlements, and a findings engine.
// Sibling tool to peinfo (github.com/redduxz/peinfo).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	flagJSON     = flag.Bool("json", false, "emit JSON")
	flagAll      = flag.Bool("all", false, "scan: include files with no findings")
	flagFindings = flag.Bool("findings-only", false, "single-file: print only findings")
	flagProcs    = flag.Bool("procs", false, "triage all running processes")
)

func usage() {
	fmt.Fprintf(os.Stderr, `machoinfo — Mach-O binary triage

usage:
  machoinfo <file>            full triage of one binary
  machoinfo <dir>             recursively scan binaries, print flagged ones
  machoinfo --procs           triage all running processes
flags:
  --json             emit JSON
  --all              in dir/procs mode, also print clean binaries
  --findings-only    in file mode, print findings only
`)
	os.Exit(2)
}

func main() {
	flag.Parse()
	args := flag.Args()

	if *flagProcs {
		runProcs()
		return
	}
	if len(args) == 0 {
		usage()
	}

	info, err := os.Stat(args[0])
	if err != nil {
		fatal(err)
	}

	if info.IsDir() {
		runScan(args[0])
		return
	}

	// single file
	rep, err := Analyze(args[0])
	if err != nil {
		fatal(err)
	}
	if *flagJSON {
		emitJSON(rep)
		return
	}
	if *flagFindings {
		for _, f := range rep.Findings {
			fmt.Println(f)
		}
		return
	}
	printReport(rep)
}

func runScan(root string) {
	var reps []*Report
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rep, err := Analyze(p)
		if err != nil {
			return nil // not a Mach-O, unreadable, etc — skip
		}
		reps = append(reps, rep)
		return nil
	})
	if err != nil {
		fatal(err)
	}
	printScan(reps)
}

func runProcs() {
	var reps []*Report
	seen := map[string]bool{}
	for _, p := range procPaths() {
		if seen[p] {
			continue
		}
		seen[p] = true
		rep, err := Analyze(p)
		if err != nil {
			continue
		}
		reps = append(reps, rep)
	}
	printScan(reps)
}

func printScan(reps []*Report) {
	sort.Slice(reps, func(i, j int) bool {
		return len(reps[i].Findings) > len(reps[j].Findings)
	})
	if *flagJSON {
		emitJSON(reps)
		return
	}
	flagged := 0
	for _, r := range reps {
		if len(r.Findings) == 0 && !*flagAll {
			continue
		}
		flagged++
		fmt.Printf("%s\n", r.Path)
		printSummaryLine(r)
		for _, f := range r.Findings {
			fmt.Printf("    ⚑ %s\n", f)
		}
	}
	fmt.Printf("\n%d/%d binaries flagged\n", flagged, len(reps))
}

func emitJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "machoinfo:", err)
	os.Exit(1)
}

// helper used by output.go
func hasStr(s []string, sub string) bool {
	for _, x := range s {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
