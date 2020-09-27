# rapg

Rapg is a password manager that allows you to generate and manage strong passwords.
It stands for Random Password Generator.
We think of it as being inspired by gopass.

## Installation
from Github
```
git clone https://github.com/kanywst/rapg
cd rapg/cmd/rapg
go build .
mv rapg /usr/local/bin
```
## Usage
```
$ rapg -h                                                                                                                                                                          +[master]
NAME:
   Rapg - rapg is a tool for generating and managing random, strong passwords.

USAGE:
   rapg [global options] command [command options] [arguments...]

COMMANDS:
   add         add password
   init        initialize
   search, s   search password
   list        list password
   remove, rm  remove password
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --len value, -l value  password length (default: 24)
   --help, -h             show help
```