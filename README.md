# rapg

Rapg is a password manager that allows you to generate and manage strong passwords.
It stands for Random Password Generator.
We think of it as being inspired by gopass.

## Installation
### from Github
```
git clone https://github.com/kanywst/rapg
cd rapg/cmd/rapg
go build .
mv rapg /usr/local/bin
```
## Usage

### Basic Usage
Simply, rapg can be run with:
```
$ rapg
```

### Flags
```
$ rapg -h                                                                                                                                                                          +[master]
NAME:
   Rapg - rapg is a tool for generating and managing random, strong passwords.

USAGE:
   rapg [global options] command [command options] [arguments...]

COMMANDS:
   add         add password
   init        initialize
   show, s     show password
   list        list password
   remove, rm  remove password
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --len value, -l value  password length (default: 24)
   --help, -h             show help
```

### Generate random passwords of specified length
You can generate a password of length 100: 
```
$ rapg -l 100
```

### Create a key to encrypt and store the password
This is the first command you have to run:
```
$ rapg init
```

### Add password with a specific domain and username set
Add a password for the user test on twitter.com:
```
$ rapg add twitter.com/test
```
A password will be generated.

### Remove password with a specific domain and username set
Remove a password for the user test on twitter.com:
```
$ rapg remove twitter.com/test
```

### Show the list of passwords
```
$ rapg list
twitter.com/test
```
### Displays the stored password.
```
$ rapg show twitter.com/test
```
The password will be displayed.

## License
rapg released under MIT. See LICENSE for more details.