package util

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

// PrintfAsync prints the given message for an asynchronous event. More
// precisely, the message is prepended with a newline and appended with the
// command prefix.
func PrintfAsync(format string, a ...interface{}) {
	fmt.Printf("\r")
	logrus.Printf(format, a...)
	fmt.Printf(Format(BLUE, "\n>") + " ")
}
