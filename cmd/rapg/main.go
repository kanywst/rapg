package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/kanywst/rapg/internal/out"
	"github.com/kanywst/rapg/pkg/rapg/api"
	"github.com/urfave/cli"
)

var (
	homePath, _ = os.UserHomeDir()
	keyPath     = filepath.Join(homePath, ".rapg", ".key_store")
)

func main() {
	if _, err := os.Stat(filepath.Join(homePath, ".rapg")); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(homePath, ".rapg"), 0755)
	}

	app := cli.NewApp()
	app.Name = "Rapg"
	app.Usage = "rapg is a tool for generating and managing random, strong passwords."

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "len, l",
			Value: 24,
			Usage: "password length",
		},
	}

	app.Action = func(c *cli.Context) error {
		mrp, err := api.MakeRandomPassword(c.Int("len"))
		if err != nil {
			log.Fatal(err)
		}
		out.Green(mrp)
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
					Name:  "len, l",
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
