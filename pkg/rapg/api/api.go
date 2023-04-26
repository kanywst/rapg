package api

import (
	"crypto/aes"
	"crypto/rand"
	"os"
	"strings"
	"unsafe"

	"github.com/jinzhu/gorm"
	"github.com/kanywst/rapg/internal/crypto"
	"github.com/kanywst/rapg/internal/out"
)

type Record struct {
	Url      string
	Username string
	Password string
}

var (
	commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
)

var (
	homePath, _ = os.UserHomeDir()
	dbPath      = homePath + "/.rapg/pass.db"
	keyPath     = homePath + "/.rapg/.key_store"
)

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

func CreateKey() {
	f, err := os.OpenFile(keyPath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := make([]byte, 32)
	n, err := f.Read(buf)
	if err != nil {
		panic(err)
	}
	readResult := buf[:n]
	getKeyStore := (*(*string)(unsafe.Pointer(&readResult)))
	if getKeyStore == "" {
		key := MakeRandomPassword(32)
		f.WriteString(key)
		out.Yellow("Created key.\nSaved at ~/.rapg/.key_store.")
	} else {
		out.Red("Already exists.")
	}
}

func ShowPassword(term string) {
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
	decrypted_pass, _ := crypto.MakeDecrypt(c, pass, key, commonIV)
	decrypted_pass_string := (*(*string)(unsafe.Pointer(&decrypted_pass)))
	out.Green(decrypted_pass_string)
}

func ShowList() {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var records []Record

	db.Find(&records)

	for _, data := range records {
		out.Yellow(data.Url + "/" + data.Username)
	}
}

func AddPassword(term string, passlen int) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record
	slice := strings.Split(term, "/")

	url := slice[0]
	username := slice[1]

	tableCheck := db.HasTable(&Record{})
	if tableCheck {
		db.Find(&record, "url = ? AND username = ?", url, username)
	}
	if tableCheck && record.Url == url {
		out.Red("Already url/username")
	} else {
		key, err := readKeyFile()
		if err != nil {
			panic(err)
		}

		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		pass := MakeRandomPassword(passlen)
		out.Green(pass)

		encrypted_pass, _ := crypto.MakeEncrypt(c, []byte(pass), key, commonIV)
		encrypted_pass_string := (*(*string)(unsafe.Pointer(&encrypted_pass)))

		db.AutoMigrate(&Record{})
		db.Create(&Record{Url: url, Username: username, Password: encrypted_pass_string})
	}
}

func RemovePassword(term string) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record

	slice := strings.Split(term, "/")
	db.Where("url = ? AND username = ?", slice[0], slice[1]).Delete(&record)
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
	if err != nil {
		panic(err)
	}
	key := buf[:n]

	return key, nil
}
