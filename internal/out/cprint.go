package out

import (
	"fmt"
)

var (
	blackString   = "\x1b[30m%s\x1b[0m\n"
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