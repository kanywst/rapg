package api

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
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

func MakeRandomPassword(digit int) (string, error) {
	const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@^_{|}~"

	b := make([]byte, digit)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	var result strings.Builder
	for _, v := range b {
		result.WriteByte(letters[int(v)%len(letters)])
	}
	return result.String(), nil
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
	getKeyStore := *(*string)(unsafe.Pointer(&readResult))
	if getKeyStore == "" {
		key, err := MakeRandomPassword(32)
		if err != nil {
			panic(err)
		}
		if _, err := f.Write([]byte(key)); err != nil {
			panic(err)
		}
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
	if err := db.Find(&record, "url = ? AND username = ?", slice[0], slice[1]).Error; err != nil {
		panic(err)
	}
	pass := []byte(record.Password)

	// Convert cipher.Block to []byte
	ciphertext := make([]byte, len(pass))
	c.Encrypt(ciphertext, pass)

	decryptedPass, err := crypto.DecryptAES(ciphertext, key, commonIV)
	if err != nil {
		panic(err)
	}
	out.Green(string(decryptedPass))
}

func ShowList() {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Println("failed to connect database:", err)
		return
	}
	defer db.Close()

	var records []Record

	if err := db.Find(&records).Error; err != nil {
		fmt.Println("failed to retrieve records:", err)
		return
	}

	for _, data := range records {
		out.Yellow(data.Url + "/" + data.Username)
	}
}

func AddPassword(term string, passlen int) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Println("failed to connect database:", err)
		return
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

		pass, err := MakeRandomPassword(passlen)
		if err != nil {
			fmt.Println("failed to generate password:", err)
			return
		}
		out.Green(pass)

		encryptedPass, err := crypto.EncryptAES([]byte(pass), key, commonIV)
		if err != nil {
			panic(err)
		}
		_ = encryptedPass // Unused variable removed

		db.AutoMigrate(&Record{})
		if err := db.Create(&Record{Url: url, Username: username, Password: string(encryptedPass)}).Error; err != nil {
			fmt.Println("failed to create record:", err)
			return
		}
	}
}

func RemovePassword(term string) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Println("failed to connect database:", err)
		return
	}
	defer db.Close()

	slice := strings.Split(term, "/")
	if err := db.Where("url = ? AND username = ?", slice[0], slice[1]).Delete(&Record{}).Error; err != nil {
		fmt.Println("failed to delete record:", err)
		return
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
	defer f.Close()

	buf := make([]byte, 32)
	n, err := f.Read(buf)
	if err != nil {
		panic(err)
	}
	key := buf[:n]

	return key, nil
}
