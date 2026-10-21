package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// nonTTY persists so buffered piped input isn't dropped between calls.
var nonTTY = bufio.NewReader(os.Stdin)

// Line editor: history, arrows, tab-completion, cursor motion,
// ctrl-a/e/k/l/u, backspace + forward-delete. Returns (line, ok); ok=false = EOF.
func readLine(prompt string, hist *[]string, complete func(word string, first bool) []string) (string, bool) {
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

	buf := []rune{}
	pos := 0
	hi := len(*hist)
	var saved []rune
	lastTab := false

	render := func() {
		fmt.Fprintf(os.Stderr, "\r%s%s\x1b[K\r%s%s", prompt, string(buf), prompt, string(buf[:pos]))
	}
	rd := func() (byte, bool) {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if n == 0 || err != nil {
			return 0, false
		}
		return b[0], true
	}
	// read a full rune (handles split multibyte sequences)
	runeAt := func(b0 byte) (rune, bool) {
		rb := []byte{b0}
		for !utf8.FullRune(rb) {
			c, ok := rd()
			if !ok {
				return 0, false
			}
			rb = append(rb, c)
		}
		r, _ := utf8.DecodeRune(rb)
		return r, true
	}

	render()
	for {
		c0, ok := rd()
		if !ok {
			return "", false
		}
		tab := false

		switch {
		case c0 == 0x1b: // CSI / SS3 sequence
			b1, ok := rd()
			if !ok || (b1 != '[' && b1 != 'O') {
				continue
			}
			var seq []byte
			for {
				b, ok := rd()
				if !ok {
					break
				}
				seq = append(seq, b)
				if b >= 0x40 && b <= 0x7e {
					break // final byte
				}
			}
			code := string(seq)
			switch code {
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
			case "3~": // forward delete
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
		case c0 >= 0x20 || c0 >= 0x80:
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
