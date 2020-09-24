package main

import (
	"fmt"
	"crypto/rand"
	"errors"
	"flag"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"unsafe"
	"os"
)

// Option
var (
	showAll = flag.Bool("a", false, "Show All Password.")
	setKey = flag.String("i", "null", "Set Domain/Username for passsword.")
	searchPassword = flag.String("s", "null", "Search for Password.")
	setPasswordLength = flag.Int("l", 20, "Set Password Length.")
	setCreateKey = flag.Bool("c", false, "Create AES Key.") 
)

type Record struct{
	Url string
	Username string
	Password string
}

type Block interface {
    BlockSize() int
    Encrypt(dst, src []byte)
    Decrypt(dst, src []byte)
}

func main(){
	flag.Parse()

	var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	//データベースに接続
	db, err := gorm.Open("sqlite3", "pass.db")
	if err != nil{
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record
	var records []Record

	if *setKey != "null"{
		//keyの読み込み
		key,err := readKeyFile()
		if err != nil{
			panic(err)
		}
		
		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		//指定された文字数でパスワード生成
		pass, _ := MakeRandomPassword(*setPasswordLength)
		fmt.Println(pass)

		//パスワードを暗号化
		encrypted_pass,_ := MakeEncrypt(c, []byte(pass), key, commonIV)
		encrypted_pass_string := (*(*string)(unsafe.Pointer(&encrypted_pass)))
		//fmt.Println(encrypted_pass_string)

		slice := strings.Split(*setKey,"/")

		url := slice[0]
		username := slice[1]

		db.AutoMigrate(&Record{})
		db.Create(&Record{Url: url, Username: username, Password: encrypted_pass_string})
	}else if *showAll != false {
		db.Find(&records)

		for _, data := range records{
			fmt.Println(data.Url + "/" + data.Username)
		}
	}else if *searchPassword != "null" {
		//keyの読み込み
		key,err := readKeyFile()
		if err != nil{
			panic(err)
		}

		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		slice := strings.Split(*searchPassword,"/")
		db.Find(&record, "url = ? AND username = ?",slice[0],slice[1])
		pass := []byte(record.Password)
		decrypted_pass,_ := MakeDecrypt(c, pass, key, commonIV)
		decrypted_pass_string := (*(*string)(unsafe.Pointer(&decrypted_pass)))
		//fmt.Println(record.Password)
		fmt.Println(decrypted_pass_string)
	}else if *setCreateKey != false{
		result,_ := CreateKey();
		fmt.Println(result)
	}else {
		//指定された文字数でパスワード生成
		pass, _ := MakeRandomPassword(*setPasswordLength)
		fmt.Println(pass)
	}
}

// Create Random Password
func MakeRandomPassword(digit int) (string,error){
	const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@^_{|}~"

	b := make([]byte,digit)
	if _,err := rand.Read(b); err != nil{
		return "",errors.New("unexpected error...")
	}

	var result string
	for _,v := range b{
		result += string(letters[int(v)%len(letters)])
	}
	return result, nil
}

// AES Encrypt
func MakeEncrypt(c Block, text []byte, key []byte, commonIV []byte) ([]byte, error){
	cfb := cipher.NewCFBEncrypter(c, commonIV)
	result := make([]byte,len(text))
	cfb.XORKeyStream(result, text)

	return result, nil
}
// AES Decrypt
func MakeDecrypt(c Block, text []byte, key []byte, commonIV []byte) ([]byte, error){
	cfbdec := cipher.NewCFBDecrypter(c, commonIV)
	result := make([]byte, len(text))
	cfbdec.XORKeyStream(result, text)

	return result,nil
}
// Create AES Key
func CreateKey() (string,error) {
	f, err := os.OpenFile(".key_store", os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := make([]byte, 32)
	n,err := f.Read(buf)
	readResult := buf[:n]
	getKeyStore := (*(*string)(unsafe.Pointer(&readResult)))
	//fmt.Println(getKeyStore)
	if getKeyStore == "" {
		unko,_ := MakeRandomPassword(32)
		f.WriteString(unko)
		return "Created key.\nSaved at .key_store.", nil
	}else{
		return "Already exists.", nil
	}
}
// Read File
func readKeyFile()([]byte,error){
	f, err := os.OpenFile(".key_store", os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil,err
		}
		return nil,err
	}
	buf := make([]byte, 32)
	n,err := f.Read(buf)
	key := buf[:n]

	return key,nil
}