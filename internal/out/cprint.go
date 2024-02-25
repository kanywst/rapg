package out

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	white   = color.New(color.FgWhite).SprintFunc()
)

func Red(pass string) {
	fmt.Printf("%s\n", red(pass))
}

func Yellow(pass string) {
	fmt.Printf("%s\n", yellow(pass))
}

func Green(pass string) {
	fmt.Printf("%s\n", green(pass))
}

func Blue(pass string) {
	fmt.Printf("%s\n", blue(pass))
}

func Cyan(pass string) {
	fmt.Printf("%s\n", cyan(pass))
}

func Magenta(pass string) {
	fmt.Printf("%s\n", magenta(pass))
}

func White(pass string) {
	fmt.Printf("%s\n", white(pass))
}
