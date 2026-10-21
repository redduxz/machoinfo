package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Minimal interactive line editor: history, arrows, cursor motion,
// ctrl-a/e/k/l/u, backspace/delete. Returns (line, ok); ok=false = EOF.
func readLine(prompt string, hist *[]string) (string, bool) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		// not a tty - plain line read
		br := bufio.NewReader(os.Stdin)
		line, rerr := br.ReadString('\n')
		if rerr != nil && line == "" {
			return "", false
		}
		return strings.TrimRight(line, "\r\n"), true
	}
	defer term.Restore(fd, old)

	buf := []rune{}
	pos := 0
	hi := len(*hist) // history index (== len = editing fresh)
	var saved []rune // stash current line when browsing history

	render := func() {
		fmt.Fprintf(os.Stderr, "\r%s%s\x1b[K\r%s%s", prompt, string(buf), prompt, string(buf[:pos]))
	}
	render()

	for {
		var b [4]byte
		n, err := os.Stdin.Read(b[:])
		if n == 0 || err != nil {
			return "", false
		}
		c := b[0]

		if c == 0x1b && n >= 2 { // escape sequence
			if b[1] != '[' && b[1] != 'O' {
				continue
			}
			var code byte
			if n >= 3 {
				code = b[2]
			} else {
				os.Stdin.Read(b[2:3])
				code = b[2]
			}
			switch code {
			case 'A': // up
				if hi > 0 {
					if hi == len(*hist) {
						saved = append([]rune{}, buf...)
					}
					hi--
					buf = []rune((*hist)[hi])
					pos = len(buf)
				}
			case 'B': // down
				if hi < len(*hist) {
					hi++
					if hi == len(*hist) {
						buf = saved
					} else {
						buf = []rune((*hist)[hi])
					}
					pos = len(buf)
				}
			case 'C': // right
				if pos < len(buf) {
					pos++
				}
			case 'D': // left
				if pos > 0 {
					pos--
				}
			case 'H', '1': // home
				pos = 0
			case 'F', '4': // end
				pos = len(buf)
			}
			render()
			continue
		}

		switch {
		case c == 0x03: // ctrl-c
			fmt.Fprint(os.Stderr, "\r\n")
			return "", true // signal: empty line, keep shell alive
		case c == 0x04: // ctrl-d
			if len(buf) == 0 {
				return "", false
			}
		case c == 0x0c: // ctrl-l
			fmt.Fprint(os.Stderr, "\x1b[2J\x1b[H")
		case c == 0x01: // ctrl-a
			pos = 0
		case c == 0x05: // ctrl-e
			pos = len(buf)
		case c == 0x0b: // ctrl-k
			buf = buf[:pos]
		case c == 0x15: // ctrl-u
			buf = buf[pos:]
			pos = 0
		case c == '\r' || c == '\n':
			fmt.Fprint(os.Stderr, "\r\n")
			return string(buf), true
		case c == 0x7f || c == 0x08: // backspace
			if pos > 0 {
				buf = append(buf[:pos-1], buf[pos:]...)
				pos--
			}
		case c >= 0x20: // printable
			r, _ := utf8.DecodeRune(b[:n])
			buf = append(buf[:pos], append([]rune{r}, buf[pos:]...)...)
			pos++
		}
		render()
	}
}
