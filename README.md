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
$ rapg -h                                                                                                                                                                           [master]
Usage of rapg:
  -a    Show All Password.
  -c    Create AES Key.
  -i string
        Set Domain/Username for passsword. (default "null")
  -l int
        Set Password Length. (default 20)
  -s string
```