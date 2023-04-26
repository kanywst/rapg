package out

import (
	"fmt"
)

var (
	redString     = "\x1b[31m%s\x1b[0m\n"
	greenString   = "\x1b[32m%s\x1b[0m\n"
	yellowString  = "\x1b[33m%s\x1b[0m\n"
	blueString    = "\x1b[34m%s\x1b[0m\n"
	magentaString = "\x1b[35m%s\x1b[0m\n"
	cyanString    = "\x1b[36m%s\x1b[0m\n"
	whiteString   = "\x1b[37m%s\x1b[0m\n"
)

func Red(pass string) {
	fmt.Printf(redString, pass)
}

func Yellow(pass string) {
	fmt.Printf(yellowString, pass)
}

func Green(pass string) {
	fmt.Printf(greenString, pass)
}

func Blue(pass string) {
	fmt.Printf(blueString, pass)
}

func Cyan(pass string) {
	fmt.Printf(cyanString, pass)
}

func Magenta(pass string) {
	fmt.Printf(magentaString, pass)
}

func White(pass string) {
	fmt.Printf(whiteString, pass)
}
