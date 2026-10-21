package main

import (
	"fmt"
	"os"
	"time"
)

var logo = []string{
	`███╗   ███╗ █████╗  ██████╗██╗  ██╗ ██████╗ ██╗███╗   ██╗███████╗ ██████╗`,
	`████╗ ████║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║████╗  ██║██╔════╝██╔═══██╗`,
	`██╔████╔██║███████║██║     ███████║██║   ██║██║██╔██╗ ██║█████╗  ██║   ██║`,
	`██║╚██╔╝██║██╔══██║██║     ██╔══██║██║   ██║██║██║╚██╗██║██╔══╝  ██║   ██║`,
	`██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║╚██████╔╝██║██║ ╚████║██║     ╚██████╔╝`,
	`╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝`,
}

var tagline = `            mach-o binary triage · peinfo for macos`

// printBanner draws the logo (animated reveal when interactive).
func printBanner() {
	anim := useColor
	delay := 0
	if anim {
		delay = 28
	}
	for i, l := range logo {
		// gradient: red -> magenta across the block
		fmt.Println(gradLine(l, i))
		if anim {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
	fmt.Println(dim(tagline))
	fmt.Println()
}

// gradLine colors a banner line top→bottom through a small palette.
func gradLine(s string, i int) string {
	if !useColor {
		return s
	}
	codes := []string{"31", "31", "35", "35", "36", "36"} // red → magenta → cyan
	return paint(codes[i%len(codes)], s)
}

// spinner runs a braille spinner+message on stderr until done closes.
type spinner struct {
	done chan struct{}
	msg  func() string
}

func startSpinner(msg func() string) *spinner {
	s := &spinner{done: make(chan struct{}), msg: msg}
	if !useColor {
		return s // no spinner on pipes
	}
	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-s.done:
				fmt.Fprintf(os.Stderr, "\r%*s\r", 60, "")
				return
			default:
				fmt.Fprintf(os.Stderr, "\r %s %s", mag(frames[i%len(frames)]), dim(s.msg()))
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
	return s
}

func (s *spinner) stop() { close(s.done) }
