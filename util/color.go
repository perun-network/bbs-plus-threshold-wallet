package util

import "fmt"

const escape = "\x1b"

const (
	NONE = iota
	RED
	GREEN
	YELLOW
	BLUE
	PURPLE
)

// color changes the test output to the respective color.
func color(c int) string {
	if c == NONE {
		return fmt.Sprintf("%s[%dm", escape, c)
	}
	return fmt.Sprintf("%s[3%dm", escape, c)
}

// Format changes the given string to the respective color and returns it.
func Format(c int, text string) string {
	return color(c) + text + color(NONE)
}
