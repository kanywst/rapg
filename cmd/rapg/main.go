package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/urfave/cli"
	"os"
	"strings"
	"unsafe"
)

var (
	commonIV    = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	homePath, _ = os.UserHomeDir()
	dbPath      = homePath + "/.rapg/pass.db"
	keyPath     = homePath + "/.rapg/.key_store"
)

var (
	black   = "\x1b[30m%s\x1b[0m\n"
	red     = "\x1b[31m%s\x1b[0m\n"
	green   = "\x1b[32m%s\x1b[0m\n"
	yellow  = "\x1b[33m%s\x1b[0m\n"
	blue    = "\x1b[34m%s\x1b[0m\n"
	magenta = "\x1b[35m%s\x1b[0m\n"
	cyan    = "\x1b[36m%s\x1b[0m\n"
	white   = "\x1b[37m%s\x1b[0m\n"
)

type Record struct {
	Url      string
	Username string
	Password string
}

type Block interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

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
		cprint(green, MakeRandomPassword(c.Int("len")))
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:  "add",
			Usage: "add password",
			Action: func(c *cli.Context) error {
				if !checkKeyStore() {
					cprint(red, "At first, rapg init")
				} else {
					addPassword(c.Args().First(), c.Int("len"))
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
				createKey()
				return nil
			},
		},
		{
			Name:    "show",
			Aliases: []string{"s"},
			Usage:   "show password",
			Action: func(c *cli.Context) error {
				if !checkKeyStore() {
					cprint(red, "At first, rapg init")
				} else {
					showPassword(c.Args().First())
				}
				return nil
			},
		},
		{
			Name:  "list",
			Usage: "list password",
			Action: func(c *cli.Context) error {
				showList()
				return nil
			},
		},
		{
			Name:    "remove",
			Aliases: []string{"rm"},
			Usage:   "remove password",
			Action: func(c *cli.Context) error {
				if !checkKeyStore() {
					cprint(red, "At first, rapg init")
				} else {
					removePassword(c.Args().First())
				}
				return nil
			},
		},
	}

	app.Run(os.Args)
}

// Create Random Password
func MakeRandomPassword(digit int) string {
	const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@^_{|}~"

	b := make([]byte, digit)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	var result string
	for _, v := range b {
		result += string(letters[int(v)%len(letters)])
	}
	return result
}

// AES Encrypt
func MakeEncrypt(c Block, text []byte, key []byte, commonIV []byte) ([]byte, error) {
	cfb := cipher.NewCFBEncrypter(c, commonIV)
	result := make([]byte, len(text))
	cfb.XORKeyStream(result, text)

	return result, nil
}

// AES Decrypt
func MakeDecrypt(c Block, text []byte, key []byte, commonIV []byte) ([]byte, error) {
	cfbdec := cipher.NewCFBDecrypter(c, commonIV)
	result := make([]byte, len(text))
	cfbdec.XORKeyStream(result, text)

	return result, nil
}

// Create AES Key
func createKey() {
	f, err := os.OpenFile(keyPath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := make([]byte, 32)
	n, err := f.Read(buf)
	readResult := buf[:n]
	getKeyStore := (*(*string)(unsafe.Pointer(&readResult)))
	if getKeyStore == "" {
		key := MakeRandomPassword(32)
		f.WriteString(key)
		cprint(yellow, "Created key.\nSaved at ~/.rapg/.key_store.")
	} else {
		cprint(red, "Already exists.")
	}
}

func readKeyFile() ([]byte, error) {
	f, err := os.OpenFile(keyPath, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, err
	}
	buf := make([]byte, 32)
	n, err := f.Read(buf)
	key := buf[:n]

	return key, nil
}

func showPassword(term string) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record

	key, err := readKeyFile()
	if err != nil {
		panic(err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	slice := strings.Split(term, "/")
	db.Find(&record, "url = ? AND username = ?", slice[0], slice[1])
	pass := []byte(record.Password)
	decrypted_pass, _ := MakeDecrypt(c, pass, key, commonIV)
	decrypted_pass_string := (*(*string)(unsafe.Pointer(&decrypted_pass)))
	cprint(green, decrypted_pass_string)
}

func showList() {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var records []Record

	db.Find(&records)

	for _, data := range records {
		cprint(yellow, data.Url+"/"+data.Username)
	}
}

func addPassword(term string, passlen int) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	//重複確認
	var record Record
	slice := strings.Split(term, "/")

	url := slice[0]
	username := slice[1]

	tableCheck := db.HasTable(&Record{})
	if tableCheck {
		db.Find(&record, "url = ? AND username = ?", url, username)
	}
	if tableCheck && record.Url == url {
		cprint(red, "Already url/username")
	} else {

		//keyの読み込み
		key, err := readKeyFile()
		if err != nil {
			panic(err)
		}

		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		//指定された文字数でパスワード生成
		pass := MakeRandomPassword(passlen)
		cprint(green, pass)

		//パスワードを暗号化
		encrypted_pass, _ := MakeEncrypt(c, []byte(pass), key, commonIV)
		encrypted_pass_string := (*(*string)(unsafe.Pointer(&encrypted_pass)))

		db.AutoMigrate(&Record{})
		db.Create(&Record{Url: url, Username: username, Password: encrypted_pass_string})
	}
}

func removePassword(term string) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record

	slice := strings.Split(term, "/")
	db.Where("url = ? AND username = ?", slice[0], slice[1]).Delete(&record)
}

func checkFormat(text string) bool {
	if strings.Count(text, "/") == 1 {
		return true
	} else {
		return false
	}
}

//check .key_store
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

func cprint(color string, pass string) {
	fmt.Printf(color, pass)
}
