package keystore

import (
	"fmt"
	"testing"
)

const (
	path         = "keystore.key"
	addrPre      = "TEST"
	pwd          = "123"
	fristAddrPwd = "1234"
)

func TestMnemonic(t *testing.T) {
	MnemonicExample()
}

func MnemonicExample() {
	keystore := NewKeystore(path, addrPre)
	if err := keystore.Load(); err != nil {
		keystore.CreateNewKeystore(pwd)
	}

	//_, _, err := keystore.GetNetAddr(fristAddrPwd)
	//if err != nil {
	//	panic("GetNetAddr error:" + err.Error())
	//}
	//
	//words, err := keystore.ExportMnemonic(pwd)
	//if err != nil {
	//	panic(err)
	//}
	words := "salt slush prepare manual labor van snack person achieve recycle clever join"
	fmt.Println("打印助记词:", words)
	keystore = NewKeystore(path, addrPre)
	err := keystore.ImportMnemonic(words, pwd, fristAddrPwd, fristAddrPwd)
	if err != nil {
		panic(err)
	}
	words, err = keystore.ExportMnemonic(pwd)
	if err != nil {
		panic(err)
	}
	fmt.Println("打印助记词:", words)
}
