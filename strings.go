package main

import (
	"io"
	"os"
	"regexp"
	"strings"
)

const minStrLen = 6
const maxStrLen = 160 // longer = almost certainly a packed string-blob, not a real string

var interesting = []*regexp.Regexp{
	regexp.MustCompile(`https?://[^\s"']+`),
	regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|bearer)\s*[:=]`),
	regexp.MustCompile(`(?i)\.(onion|dylib|framework|appex|xpc)\b`),
	regexp.MustCompile(`(?i)/Users/[^\s"']+`),
	regexp.MustCompile(`(?i)(socket|connect|dlopen|dlsym|mprotect|task_for_pid|ptrace|sysctl)`),
	regexp.MustCompile(`[^\s"']+@[^\s"']+\.[a-z]{2,}`),
}

// extractStrings scans the file for ASCII strings and returns the
// interesting subset (URLs, IPs, suspicious calls, creds-looking keys).
// cap limits the returned list.
func extractStrings(path string, cap int) []string {
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()

	seen := map[string]bool{}
	var out []string
	var cur strings.Builder

	flush := func() {
		if cur.Len() >= minStrLen && cur.Len() <= maxStrLen {
			s := cur.String()
			for _, re := range interesting {
				if re.MatchString(s) {
					if !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
					break
				}
			}
		}
		cur.Reset()
	}

	buf := make([]byte, 1<<16)
	for {
		n, err := fh.Read(buf)
		for i := 0; i < n; i++ {
			b := buf[i]
			if b >= 0x20 && b <= 0x7e {
				cur.WriteByte(b)
			} else {
				flush()
			}
		}
		if err == io.EOF || err != nil {
			break
		}
	}
	flush()

	if len(out) > cap {
		out = out[:cap]
	}
	return out
}
