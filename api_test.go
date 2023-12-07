package keystore

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"gitee.com/prestonTao/keystore/base58"
	"gitee.com/prestonTao/keystore/crypto"
	"gitee.com/prestonTao/utils"
	"golang.org/x/crypto/ed25519"
	"strconv"
	"sync"
	"testing"
	// "gitee.com/prestonTao/keystore/crypto"
)

func TestApi(t *testing.T) {
	useKeyStore()
	//getNetAddrTmp()
	//createNewAddrByName()
	//createNewAddr()
	//getAddrList()
	//updatePwd()
	//updateAddrPwd()
	//example1()
	// leftRecentTest()
	//getPukByAddr()
	//findAddress()
	//getCoinbase()
	//mnemonicExample()
	//dhKeyPar()
	//netAddr()
	//getAddrPwd()

	//pr, pu, err := GetNetAddrKeyByMnemonic("donor hotel girl cigar fish crater pride point attract bid want receive", wordlists.English)
	//fmt.Println("私钥：", base64.StdEncoding.EncodeToString(pr), " 公钥：", base64.StdEncoding.EncodeToString(pu), " err:", err)

	//err := RenameTempFile("D:\\vertest\\key.json")
	//fmt.Println("err::::::", err)
}

func TestApiV5(t *testing.T) {
	path := "keystore.key"
	addrPre := "IM"
	pwd := "1234567890"
	//newAddrPwd := "1234567890"
	err := Load(path, addrPre)
	if err != nil {
		err := CreateKeystore(path, addrPre, pwd)
		if err != nil {
			fmt.Println("CreateKeystore error:", err.Error())
			return
		}
	}

}

func useKeyStore() {
	path := "keystore.key"
	addrPre := "IM"
	pwd := "1234567890"
	newAddrPwd := "1234567890"
	err := Load(path, addrPre)
	if err != nil {
		err := keystoreStatic.CreateNewKeystore(pwd)
		if err != nil {
			fmt.Println("CreateKeystore error:", err.Error())
			return
		}
	}

	if keystoreStatic.NetAddr == nil {
		_, _, err = keystoreStatic.CreateNetAddr(pwd, newAddrPwd)
		if err != nil {
			fmt.Println("GetNewDHKey error:", err.Error())
			return
		}
	}

	if len(GetAddrAll()) == 0 {
		addr, err := GetNewAddr(pwd, newAddrPwd)
		if err != nil {
			fmt.Println("GetNewAddr error:", err.Error())
			return
		}
		fmt.Println(addr.B58String())
	}

	if len(GetDHKeyPair().SubKey) == 0 {
		dh, err := keystoreStatic.GetNewDHKey(pwd, newAddrPwd)
		if err != nil {
			fmt.Println("GetNewDHKey error:", err.Error())
			return
		}
		fmt.Println("DH:", dh)
	}

	//prk, puk, err := GetNetAddr(newAddrPwd)
	//fmt.Printf("GetNetAddr prk: %v  puk: %v err:%v \n", base64.StdEncoding.EncodeToString(prk), base64.StdEncoding.EncodeToString(puk), err)
	//addrPwd, err := keystoreStatic.GetNetAddrPwd(prk)
	//fmt.Println("NetAddrPwd: ", addrPwd, "err :", err)
	//ok, err := keystoreStatic.UpdateDHKeyPwd(newAddrPwd, "987654321")
	//fmt.Println("ok ", ok, " err:", err)
	//ok, err = keystoreStatic.UpdateDHKeyPwd("987654321", newAddrPwd)
	//fmt.Println("ok ", ok, " err:", err)
	//
	//ok, err = UpdateNetAddrPwd(newAddrPwd, "12345678901")
	//fmt.Println("UpdateNetAddrPwd ok ", ok, " err:", err)
	//prk, puk, err = GetNetAddr("12345678901")
	//fmt.Printf("GetNetAddr prk: %v  puk: %v err:%v \n", base64.StdEncoding.EncodeToString(prk), base64.StdEncoding.EncodeToString(puk), err)
	////fmt.Println("NetAddr:", BuildAddr(puk))
	//addrPwd, err = keystoreStatic.GetNetAddrPwd(prk)
	//fmt.Println("NetAddrPwd: ", addrPwd, "err :", err)

}

func BuildAddr(pubKey []byte) string {
	//第一步，计算SHA-256哈希值
	publicSHA256 := sha256.Sum256(pubKey)
	//第二步，计算上一步结果的SHA-256哈希值
	temp := sha256.Sum256(publicSHA256[:])
	return string(base58.Encode(temp[:]))
}

func getAddrList() {
	path := "keystore.key"
	addrPre := "TEST"
	Load(path, addrPre)
	for _, v := range GetAddrAll() {
		fmt.Println(v.Index, v.Addr.B58String())
		//_, pri, _ := GetKeyByPuk(v.Puk, "123")
		//fmt.Println(pri)
	}

}

/*
测试给地址设置名称
*/
func createNewAddrByName() {
	path := "keystore.key"
	addrPre := "TEST"
	pwd := "123"
	newAddrPwd := "123"
	err := CreateKeystore(path, addrPre, pwd)
	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < 5; i++ {
		addr, err := GetNewAddrByName(strconv.Itoa(i), pwd, newAddrPwd)
		// addr, err := GetNewAddr(pwd)
		if err != nil {
			fmt.Println("35 GetNewAddr error:", err.Error())
			break
		}
		fmt.Println(i, addr.B58String())
	}
}

var wg sync.WaitGroup

/*
创建地址数量测试
*/
func createNewAddr() {
	path := "keystore.key"
	addrPre := "IM"
	pwd := "1234567890"
	newPwd := "1234567890"
	err := CreateKeystore(path, addrPre, pwd)
	if err != nil {
		fmt.Println(err)
	}

	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr, err := GetNewAddr(pwd, newPwd)
			if err != nil {
				fmt.Println("GetNewAddr error:", err.Error())
				return
			}
			fmt.Println(i, addr.B58String())
		}(i)
		//break
	}
	wg.Wait()
}

func updatePwd() {
	path := "keystore.key"
	addrPre := "IM"
	pwd := "12345678903"
	newPwd := "1234567890"
	err := Load(path, addrPre)
	if err != nil {
		fmt.Println(err)
	}
	ok, err := UpdatePwd(pwd, newPwd)
	if err != nil {
		fmt.Println("updatePwd error:", err.Error())

	}
	fmt.Println(ok)
}

func updateAddrPwd() {
	path := "keystore.key"
	addrPre := "TEST"
	pwd := "1234"
	newPwd := "123"
	err := Load(path, addrPre)
	if err != nil {
		fmt.Println(err)
	}
	ok, err := UpdateAddrPwd("TESTLjD7cep1ppd7cUXN4K9Mj6PWpd3nnVQkM5", pwd, newPwd)
	if err != nil {
		fmt.Println("updatePwd error:", err.Error())

	}
	fmt.Println(ok)
}

func example1() {
	path := "keystore.key"
	addrPre := "IM"
	//pwd := "1234567890"
	newAddrpwd := "1234567890"
	/*err := CreateKeystore(path, addrPre, pwd)
	if err != nil {
		fmt.Println(err)
	}
	addr, err := GetNewAddr(pwd, newAddrpwd)
	if err != nil {
		fmt.Println("GetNewAddr:", err)
	}
	fmt.Println(addr.B58String())

	addrInfos := GetAddrAll()
	for _, one := range addrInfos {
		fmt.Println("遍历地址:", one.Addr.B58String())
	}
	ad := GetCoinbase()
	fmt.Println("基础地址:", ad.Addr.B58String())
	_, _, err = GetNetAddr(newAddrpwd)
	if err != nil {
		panic("GetNetAddr error:" + err.Error())
	}*/
	err := Load(path, addrPre)
	if err != nil {
		fmt.Println("加载密钥报错:", err)
	}
	//addr, err := GetNewAddr(pwd, newAddrpwd)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())
	//addr, err = GetNewAddr(pwd, newAddrpwd)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())
	addrInfos := GetAddrAll()
	for _, one := range addrInfos {
		fmt.Println("遍历地址:", one.Addr.B58String())
	}
	addr := addrInfos[0].Addr
	newAddrpwd1 := "12345678901"
	ok, err := UpdateAddrPwd(addr.B58String(), newAddrpwd, newAddrpwd1)
	fmt.Println(ok, err)

	//addr, err = GetNewAddr(pwd, newAddrpwd1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())
	//
	//addr, err = GetNewAddr(pwd, newAddrpwd1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())
	//
	//addr, err = GetNewAddr(pwd, newAddrpwd1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())
	//
	//addr, err = GetNewAddr(pwd, newAddrpwd1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())

	//addrInfos := GetAddrAll()
	//for _, one := range addrInfos {
	//	fmt.Println("遍历地址:", one.Addr.B58String())
	//}
	//	puk := addrInfos[1].Puk
	puk, _ := GetPukByAddr(addr, newAddrpwd1)
	fmt.Println("获取到的puk:", base64.StdEncoding.EncodeToString(puk))
	//_, prk, err := GetKeyByPuk(puk, newAddrpwd1)
	_, prk, puk, err := GetKeyByAddr(addr, newAddrpwd1)
	//fmt.Println(base64.StdEncoding.EncodeToString(prk))
	//fmt.Println(base64.StdEncoding.EncodeToString(puk))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("获取到的puk:", base64.StdEncoding.EncodeToString(puk))
	fmt.Println("获取到的prk:", base64.StdEncoding.EncodeToString(prk))

	srcBs := []byte(utils.GetRandomDomain())
	signBs := Sign(prk, srcBs)
	check := ed25519.Verify(puk, srcBs, signBs)
	fmt.Println("验证签名===================", check)

}

//func getPukByAddr() {
//	path := "keystore.key"
//	addrPre := "TEST"
//	Load(path, addrPre)
//	addrInfos := GetAddrAll()
//	for _, one := range addrInfos {
//		puk, ok := GetPukByAddr(one.Addr)
//		if !ok {
//			fmt.Println(ok)
//		}
//		fmt.Println("地址:", one.Addr.B58String(), " 公钥：", hex.EncodeToString(puk))
//	}
//
//}

func findAddress() {
	path := "keystore.key"
	addrPre := "TEST"
	Load(path, addrPre)
	ainfo, ok := FindAddress(crypto.AddressFromB58String("TESTPc8ibqr8GY7EkDVqjhZnqMPTkoJKszubp5"))
	fmt.Println(ok, "地址:", ainfo.Addr.B58String())
}

//func getCoinbase() {
//	path := "keystore.key"
//	addrPre := "TEST"
//	Load(path, addrPre)
//	addrInfos := GetAddrAll()
//	for _, one := range addrInfos {
//		puk, ok := GetPukByAddr(one.Addr)
//		if !ok {
//			fmt.Println(ok)
//		}
//		fmt.Println("地址:", one.Addr.B58String(), " 公钥：", hex.EncodeToString(puk))
//	}
//	fmt.Println("基础地址:", GetCoinbase().Addr.B58String())
//	SetCoinbase(2)
//	fmt.Println("修改后基础地址:", GetCoinbase().Addr.B58String())
//}

func mnemonicExample() {
	path := "keystore.key"
	addrPre := "IM"
	pwd := "1234567890"
	newAddrPwd := "1234567890"
	Load(path, addrPre)
	//words, err := ExportMnemonic(pwd)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(words)

	words := "hour street again define million camera clean violin tunnel cattle flee daughter"
	err := ImportMnemonic(words, pwd, newAddrPwd, newAddrPwd)
	if err != nil {
		fmt.Println(err)
	}
	//err := ImportMnemonicCreateMoreCoinAddr(words, pwd, newAddrPwd, newAddrPwd, 2)
	//if err != nil {
	//	fmt.Println(err)
	//}
	words, err = ExportMnemonic(pwd)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(words)
}

func dhKeyPar() {
	path := "keystore.key"
	addrPre := "TEST"
	pwd := "12345"
	newPwd := "1234"
	Load(path, addrPre)
	ok, err := UpdateDHKeyPwd(pwd, newPwd)
	if err != nil {
		fmt.Println("update dhKeyPwd error:", err.Error())

	}
	fmt.Println(ok)
}

func netAddr() {
	path := "keystore.key"
	addrPre := "IM"
	//pwd := "0000000000"
	addrPwd := "abcdef"
	//addrPwd := "123456789"
	//newAddrPwd := "1234"
	Load(path, addrPre)

	//addr, err := GetNewAddr(pwd, addrPwd)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(addr.B58String())

	prk, puk, err := GetNetAddr(addrPwd)
	fmt.Printf("prk: %v  puk: %v err:%v \n", base64.StdEncoding.EncodeToString(prk), base64.StdEncoding.EncodeToString(puk), err)

	//ok, err := UpdateNetAddrPwd(addrPwd, newAddrPwd)
	//fmt.Println("ok:", ok, "         err:", err)
}

func getNetAddrTmp() {
	pr, err := base64.StdEncoding.DecodeString("6DVd7zB5vK3aQqMTNlc2hIFbsUh1qy3vAfUaT9OIl9ZOhsG8Z1KU4UypuTcwHEx9DV606F47+69XcoxbmEyl8A==")
	if err != nil {
		fmt.Println("DecodeString err :", err.Error())
		return
	}
	//pre := ed25519.PrivateKey(pr).Seed()
	//Sec, err := crypto.EncryptCBC([]byte("123456789"), pre, Salt)
	//if err != nil {
	//	fmt.Println("EncryptCBC: ", err)
	//}
	//p, err := crypto.DecryptCBC(Sec, pre, Salt)
	//if err != nil {
	//	fmt.Println("DecryptCBC: ", err)
	//}
	//fmt.Println("Sec: ", Sec, " pwd: ", string(p))
	//return
	keystore := NewKeyStoreTmpNetAddr(pr)
	prk, puk, err := keystore.GetNetAddr("")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("puk ", base64.StdEncoding.EncodeToString(puk))
	srcBs := []byte(utils.GetRandomDomain())
	signBs := Sign(prk, srcBs)
	check := ed25519.Verify(puk, srcBs, signBs)
	fmt.Println("验证签名===================", check)

	path := "keystore.key"
	addrPre := "IM"
	pwd := "1234567890"
	keystore.SetKeyStore(path, addrPre)
	//fmt.Println(err)
	prk, puk, err = keystore.GetNetAddr(pwd)

	signBs = Sign(prk, srcBs)
	check = ed25519.Verify(puk, srcBs, signBs)
	fmt.Println("验证签名===================", check)
}

func getAddrPwd() {
	path := "keystore.key"
	addrPre := "IM"
	pwd := "1234567890"
	err := Load(path, addrPre)
	if err != nil {
		err := CreateKeystore(path, addrPre, pwd)
		if err != nil {
			fmt.Println("CreateKeystore error:", err.Error())
			return
		}
	}
	pr, _, err := keystoreStatic.GetNetAddr("1234567890")
	p, err := keystoreStatic.GetNetAddrPwd(pr)
	fmt.Println(p, err)

	ok, err := keystoreStatic.UpdateNetAddrPwd("1234567890", pwd)
	fmt.Println("ok: ", ok, "err: ", err)
	p, err = keystoreStatic.GetNetAddrPwd(pr)
	fmt.Println(p, err)
}
