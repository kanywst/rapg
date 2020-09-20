package main

import (
	"fmt"
	"crypto/rand"
	"errors"
	"flag"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
)

// オプション
var (
	showAll = flag.Bool("a", false, "Show All Password.")
	setKeyword = flag.String("k", "null", "Set Keyword for passsword.")
	setUsername = flag.String("u","null","Set Username.")
	searchPassword = flag.String("s", "null", "Search for Password.")
	setPasswordLength = flag.Int("l", 20, "Set Password Length")
)

type Record struct{
	Keyword string
	Username string
	Password string
}

func main(){
	//複数個指定したらエラー吐くようにしたほうがいい???
	flag.Parse()

	//データベースに接続
	db, err := gorm.Open("sqlite3", "pass.db")
	if err != nil{
		panic("failed to connect database")
	}
	defer db.Close()

	var record Record
	var records []Record

	if *setKeyword != "null"{
		//指定された文字数でパスワード生成
		pass, _ := MakeRandomPassword(*setPasswordLength)
		fmt.Println(pass)

		keyword := *setKeyword
		username := *setUsername

		// Migrate
		db.AutoMigrate(&Record{})

		// Create
		// 同じkeywordに対して、多重登録を防ぐ処理が必要
		db.Create(&Record{Keyword: keyword, Username: username, Password: pass})
	}else if(*showAll != false){
		db.Find(&records)
		fmt.Println(records)
	}else if(*searchPassword != "null"){
		db.Find(&record, "keyword = ?",*searchPassword)
		fmt.Println(record)
	}else{
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