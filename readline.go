package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// nonTTY persists so buffered piped input isn't dropped between calls.
var nonTTY = bufio.NewReader(os.Stdin)

// stdinCh streams raw stdin bytes; one reader goroutine for the process.
var (
	stdinCh   chan byte
	stdinOnce sync.Once
)

func stdinBytes() <-chan byte {
	stdinOnce.Do(func() {
		stdinCh = make(chan byte, 256)
		go func() {
			var b [1]byte
			for {
				n, err := os.Stdin.Read(b[:])
				if n > 0 {
					stdinCh <- b[0]
				}
				if err != nil {
					return
				}
			}
		}()
	})
	return stdinCh
}

// Line editor: history, arrows, tab-completion, cursor motion,
// ctrl-a/e/k/l/u, backspace + forward-delete, idle prompt pulse.
// promptFn(alt) returns the prompt; alt toggles while idle.
func readLine(promptFn func(bool) string, hist *[]string, complete func(word string, first bool) []string) (string, bool) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		line, rerr := nonTTY.ReadString('\n')
		if rerr != nil && line == "" {
			return "", false
		}
		return strings.TrimRight(line, "\r\n"), true
	}
	defer term.Restore(fd, old)

	ch := stdinBytes()
	buf := []rune{}
	pos := 0
	hi := len(*hist)
	var saved []rune
	lastTab := false
	alt := false

	render := func() {
		p := promptFn(alt)
		fmt.Fprintf(os.Stderr, "\r%s%s\x1b[K\r%s%s", p, string(buf), p, string(buf[:pos]))
	}
	next := func() (byte, bool) {
		c, ok := <-ch
		return c, ok
	}
	runeAt := func(b0 byte) (rune, bool) {
		rb := []byte{b0}
		for !utf8.FullRune(rb) {
			c, ok := next()
			if !ok {
				return 0, false
			}
			rb = append(rb, c)
		}
		r, _ := utf8.DecodeRune(rb)
		return r, true
	}

	tick := time.NewTicker(550 * time.Millisecond)
	defer tick.Stop()

	render()
	for {
		select {
		case <-tick.C:
			alt = !alt
			render()
			continue
		case c0, ok := <-ch:
			if !ok {
				return "", false
			}
			tab := false

			switch {
			case c0 == 0x1b: // CSI / SS3 sequence
				b1, ok := next()
				if !ok || (b1 != '[' && b1 != 'O') {
					continue
				}
				var seq []byte
				for {
					b, ok := next()
					if !ok {
						break
					}
					seq = append(seq, b)
					if b >= 0x40 && b <= 0x7e {
						break
					}
				}
				switch string(seq) {
				case "A":
					if hi > 0 {
						if hi == len(*hist) {
							saved = append([]rune{}, buf...)
						}
						hi--
						buf = []rune((*hist)[hi])
						pos = len(buf)
					}
				case "B":
					if hi < len(*hist) {
						hi++
						if hi == len(*hist) {
							buf = saved
						} else {
							buf = []rune((*hist)[hi])
						}
						pos = len(buf)
					}
				case "C":
					if pos < len(buf) {
						pos++
					}
				case "D":
					if pos > 0 {
						pos--
					}
				case "H", "1~", "7~":
					pos = 0
				case "F", "4~", "8~":
					pos = len(buf)
				case "3~":
					if pos < len(buf) {
						buf = append(buf[:pos], buf[pos+1:]...)
					}
				}

			case c0 == 0x03: // ctrl-c: abandon line, keep shell
				fmt.Fprint(os.Stderr, "^C\r\n")
				return "", true
			case c0 == 0x04: // ctrl-d
				if len(buf) == 0 {
					return "", false
				}
				if pos < len(buf) {
					buf = append(buf[:pos], buf[pos+1:]...)
				}
			case c0 == 0x0c:
				fmt.Fprint(os.Stderr, "\x1b[2J\x1b[H")
			case c0 == 0x01:
				pos = 0
			case c0 == 0x05:
				pos = len(buf)
			case c0 == 0x0b:
				buf = buf[:pos]
			case c0 == 0x15:
				buf = buf[pos:]
				pos = 0
			case c0 == '\r' || c0 == '\n':
				fmt.Fprint(os.Stderr, "\r\n")
				return string(buf), true
			case c0 == 0x7f || c0 == 0x08:
				if pos > 0 {
					buf = append(buf[:pos-1], buf[pos:]...)
					pos--
				}
			case c0 == '\t':
				tab = true
				if complete != nil {
					applyCompletion(&buf, &pos, complete, lastTab)
				}
			case c0 >= 0x20:
				r, ok := runeAt(c0)
				if !ok {
					return "", false
				}
				buf = append(buf[:pos], append([]rune{r}, buf[pos:]...)...)
				pos++
			}
			lastTab = tab
			render()
		}
	}
}

// applyCompletion completes the word under the cursor. Double-tab lists options.
func applyCompletion(buf *[]rune, pos *int, complete func(string, bool) []string, lastTab bool) {
	line := string((*buf)[:*pos])
	start := len(line)
	for start > 0 && line[start-1] != ' ' && line[start-1] != '\t' {
		start--
	}
	word := line[start:]
	first := strings.TrimSpace(line[:start]) == ""
	cands := complete(word, first)
	if len(cands) == 0 {
		return
	}
	lcp := cands[0]
	for _, c := range cands[1:] {
		lcp = commonPrefix(lcp, c)
	}
	if len(lcp) > len(word) {
		rest := []rune(lcp[len(word):])
		*buf = append((*buf)[:*pos], append(rest, (*buf)[*pos:]...)...)
		*pos += len(rest)
		return
	}
	if len(cands) == 1 {
		suffix := " "
		if strings.HasSuffix(cands[0], "/") {
			suffix = ""
		}
		rest := []rune(cands[0][len(word):] + suffix)
		*buf = append((*buf)[:*pos], append(rest, (*buf)[*pos:]...)...)
		*pos += len(rest)
		return
	}
	if lastTab {
		fmt.Fprint(os.Stderr, "\r\n")
		for i, c := range cands {
			if i > 0 && i%6 == 0 {
				fmt.Fprint(os.Stderr, "\r\n")
			}
			fmt.Fprintf(os.Stderr, "  %s", c)
		}
		fmt.Fprint(os.Stderr, "\r\n")
	}
}

func commonPrefix(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return a[:i]
}
