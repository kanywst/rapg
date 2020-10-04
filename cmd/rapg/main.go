package main

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/urfave/cli"
	"os"
	"rapg/internal/out"
	"rapg/pkg/rapg/api"
)

var (
	homePath, _ = os.UserHomeDir()
	dbPath      = homePath + "/.rapg/pass.db"
	keyPath     = homePath + "/.rapg/.key_store"
)

func main() {

	if _, err := os.Stat(homePath + "/.rapg"); os.IsNotExist(err) {
		os.Mkdir(homePath+"/.rapg", 0755)
	}

	app := cli.NewApp()
	app.Name = "Rapg"
	app.Usage = "rapg is a tool for generating and managing random, strong passwords."

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "len,l",
			Value: 24,
			Usage: "password length",
		},
	}

	app.Action = func(c *cli.Context) error {
		out.Green(api.MakeRandomPassword(c.Int("len")))
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:  "add",
			Usage: "add password",
			Action: func(c *cli.Context) error {
				if !checkKeyStore() {
					out.Green("At first, rapg init")
				} else {
					api.AddPassword(c.Args().First(), c.Int("len"))
				}
				return nil
			},
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "len,l",
					Value: 24,
				},
			},
		},
		{
			Name:  "init",
			Usage: "initialize",
			Action: func(c *cli.Context) error {
				api.CreateKey()
				return nil
			},
		},
		{
			Name:    "show",
			Aliases: []string{"s"},
			Usage:   "show password",
			Action: func(c *cli.Context) error {
				if !checkKeyStore() {
					out.Red("At first, rapg init")
				} else {
					api.ShowPassword(c.Args().First())
				}
				return nil
			},
		},
		{
			Name:  "list",
			Usage: "list password",
			Action: func(c *cli.Context) error {
				api.ShowList()
				return nil
			},
		},
		{
			Name:    "remove",
			Aliases: []string{"rm"},
			Usage:   "remove password",
			Action: func(c *cli.Context) error {
				if !checkKeyStore() {
					out.Red("At first, rapg init")
				} else {
					api.RemovePassword(c.Args().First())
				}
				return nil
			},
		},
	}

	app.Run(os.Args)
}

func checkKeyStore() bool {
	_, err := os.OpenFile(keyPath, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		panic(err)
	}
	return true
}