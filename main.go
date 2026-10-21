// machoinfo - rapid Mach-O triage: headers, entropy, dylibs, rpaths,
// code signing, entitlements, and a findings engine.
// Sibling tool to peinfo (github.com/redduxz/peinfo).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"golang.org/x/term"
)

var (
	flagJSON     = flag.Bool("json", false, "emit JSON")
	flagAll      = flag.Bool("all", false, "scan: include files with no findings")
	flagFindings = flag.Bool("findings-only", false, "single-file: print only findings")
	flagProcs    = flag.Bool("procs", false, "triage all running processes")
	flagDiff     = flag.Bool("diff", false, "diff two binaries: --diff old new")
)

func usage() {
	printBanner()
	fmt.Fprintf(os.Stderr, `usage:
  machoinfo <file>            full triage of one binary
  machoinfo <dir>             recursively scan binaries, print flagged ones
  machoinfo --procs           triage all running processes
  machoinfo --diff a b        compare two binaries
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
	if *flagDiff {
		if len(args) != 2 {
			usage()
		}
		a, err := Analyze(args[0])
		if err != nil {
			fatal(err)
		}
		b, err := Analyze(args[1])
		if err != nil {
			fatal(err)
		}
		if *flagJSON {
			emitJSON(DiffReports(a, b))
		} else {
			printDiff(DiffReports(a, b))
		}
		return
	}
	if len(args) == 0 {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			runShell()
			return
		}
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
	printBanner()
	if *flagFindings {
		for _, f := range rep.Findings {
			fmt.Println(f)
		}
		return
	}
	printReport(rep)
}

func runScan(root string) {
	if !*flagJSON && !inShell {
		printBanner()
	}
	var paths []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		fatal(err)
	}
	reps := analyzePool(paths, func(done, found int) string {
		return fmt.Sprintf("scanning %s - %d/%d files, %d mach-o", root, done, len(paths), found)
	})
	printScan(reps)
}

func runProcs() {
	if !*flagJSON && !inShell {
		printBanner()
	}
	seen := map[string]bool{}
	var paths []string
	for _, p := range procPaths() {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	reps := analyzePool(paths, func(done, found int) string {
		return fmt.Sprintf("triaging processes - %d/%d", done, len(paths))
	})
	printScan(reps)
}

// analyzePool triages paths across NumCPU workers with a live spinner.
func analyzePool(paths []string, label func(done, found int) string) []*Report {
	var done, found atomic.Int64
	jobs := make(chan string, 64)
	out := make(chan *Report, 64)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if r, err := analyze(p, false); err == nil {
					out <- r
				}
				done.Add(1)
			}
		}()
	}
	go func() {
		for _, p := range paths {
			jobs <- p
		}
		close(jobs)
	}()
	go func() { wg.Wait(); close(out) }()

	sp := startSpinner(func() string { return label(int(done.Load()), int(found.Load())) })
	var reps []*Report
	for r := range out {
		reps = append(reps, r)
		found.Add(1)
	}
	sp.stop()
	return reps
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
		fmt.Printf("%s\n", bold(r.Path))
		printSummaryLine(r)
		for _, f := range r.Findings {
			fmt.Printf("      %s\n", sev(f))
		}
	}
	fmt.Printf("\n%s\n", dim(fmt.Sprintf("%d/%d binaries flagged", flagged, len(reps))))
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
