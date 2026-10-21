package main

import (
	"fmt"
	"os"
	"time"
)

// banner is the hexdump-style lockup: the Mach-O magic bytes in a chip.
func printBanner() {
	top := "╭─────────────╮"
	mid := "│ fe ed fa cf │"
	bot := "╰─────────────╯"

	if !useColor {
		fmt.Printf("%s\n%s  machoinfo\n%s   mach-o triage - peinfo for macos\n\n",
			top, mid, bot)
		return
	}
	fmt.Println(dim(top))
	time.Sleep(60 * time.Millisecond)
	fmt.Printf("%s%s  %s\n", dim("│"), cyan(" fe ed fa cf ")+dim("│"), bold("machoinfo"))
	time.Sleep(60 * time.Millisecond)
	fmt.Printf("%s  %s\n\n", dim(bot), dim("mach-o triage · peinfo for macos"))
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
