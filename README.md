# rapg

Rapg is a password manager that allows you to generate and manage strong passwords.
It stands for Random Password Generator.
We think of it as being inspired by gopass.

## Resources
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
- [rapg](#rapg)
  - [Resources](#resources)
  - [Installation](#installation)
    - [from Github](#from-github)
  - [Usage](#usage)
    - [Basic Usage](#basic-usage)
    - [Flags](#flags)
    - [Generate random passwords of specified length](#generate-random-passwords-of-specified-length)
    - [Create a key to encrypt and store the password](#create-a-key-to-encrypt-and-store-the-password)
    - [Add password with a specific domain and username set](#add-password-with-a-specific-domain-and-username-set)
    - [Remove password with a specific domain and username set](#remove-password-with-a-specific-domain-and-username-set)
    - [Show the list of passwords](#show-the-list-of-passwords)
    - [Displays the stored password](#displays-the-stored-password)
  - [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installation

### from Github

```bash
git clone https://github.com/kanywst/rapg
cd rapg/cmd/rapg
go build .
mv rapg /usr/local/bin
```

## Usage

### Basic Usage

Simply, rapg can be run with:

```bash
rapg
```

### Flags

```bash
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

```bash
rapg -l 100
```

### Create a key to encrypt and store the password

This is the first command you have to run:

```bash
rapg init
```

### Add password with a specific domain and username set

Add a password for the user test on twitter.com:

```bash
rapg add twitter.com/test
```

A password will be generated.

You can also generate and store a password of a specific length.

```bash
rapg add twitter.com/test -l 100
```

### Remove password with a specific domain and username set

Remove a password for the user test on twitter.com:

```bash
rapg remove twitter.com/test
```

### Show the list of passwords

```bash
rapg list
twitter.com/test
```

### Displays the stored password

```bash
rapg show twitter.com/test
```

The password will be displayed.

## License

rapg released under MIT. See LICENSE for more details.
