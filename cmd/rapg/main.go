package main

import (
	"fmt"
	"crypto/rand"
	"errors"
	"flag"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"strings"
)

// Option
var (
	showAll = flag.Bool("a", false, "Show All Password.")
	setKey = flag.String("i", "null", "Set Domain/Username for passsword.")
	searchPassword = flag.String("s", "null", "Search for Password.")
	setPasswordLength = flag.Int("l", 20, "Set Password Length")
)

type Record struct{
	Url string
	Username string
	Password string
}

func main(){
	flag.Parse()

	//データベースに接続
	db, err := gorm.Open("sqlite3", "pass.db")
	if err != nil{
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record
	var records []Record

	if *setKey != "null"{
		//指定された文字数でパスワード生成
		pass, _ := MakeRandomPassword(*setPasswordLength)
		fmt.Println(pass)

		slice := strings.Split(*setKey,"/")

		url := slice[0]
		username := slice[1]

		// Migrate
		db.AutoMigrate(&Record{})

		// Create
		db.Create(&Record{Url: url, Username: username, Password: pass})
	}else if *showAll != false {
		db.Find(&records)

		for _, data := range records{
			fmt.Println(data.Url + "/" + data.Username)
		}
	}else if *searchPassword != "null" {
		slice := strings.Split(*searchPassword,"/")
		db.Find(&record, "url = ? AND username = ?",slice[0],slice[1])
		fmt.Println(record.Password)
	}else {
		//指定された文字数でパスワード生成
		pass, _ := MakeRandomPassword(*setPasswordLength)
		fmt.Println(pass)
	}
}

//ランダムなPasswordを生成
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