package derivation

import (
	"encoding/base64"
	"fmt"
	"gitee.com/prestonTao/keystore/crypto"
	"github.com/tyler-smith/go-bip32"
	"testing"
)

var Salt = []byte{53, 111, 103, 103, 87, 66, 54, 103, 53, 108, 65, 81, 73, 53, 70, 43} //加密盐
func TestBipKey_CreateAddr(t *testing.T) {
	//创建助记词
	//Mnemonic, _ := CreateMnemonic(128) //128 12位 256 24位

	CoinType := uint32(66666)
	//keystore生成地址
	seed := "g9Zgj2ZxNqdevZqEVf3UgBZmLOFeusZygENClyOrQCM="
	bsByte, _ := base64.StdEncoding.DecodeString(seed) //keystore加密后的seed ==seedSec, err := crypto.EncryptCBC([]byte("seed"), []byte("1234")[:], Salt)

	rootKey, _ := bip32.NewMasterKey(bsByte)
	pub := PublicKeyForPrivateKey(rootKey.Key) //私钥转公钥
	addrs := crypto.BuildAddr("TEST", pub)     //公钥生成地址
	fmt.Println("KeyStore:", base64.StdEncoding.EncodeToString(addrs))

	Mnemonic := "vital black vicious way winter burst border roast dumb youth equal monitor"
	t.Run("keystore", func(t *testing.T) {
		//构造助记词和密码
		km, _ := NewKeyManager(Mnemonic, "1234")
		key, _ := km.GetKey(PurposeBIP44, CoinType, 0, 0, 0)
		//fmt.Println("0x" + strconv.FormatInt(int64(CoinType-Apostrophe), 16))
		//生成地址
		key.CreateAddr("TEST")

		keys, _ := km.GetMasterKey()
		pubs := PublicKeyForPrivateKey(keys.Key) //私钥转公钥
		addr := crypto.BuildAddr("TEST", pubs)   //公钥生成地址
		fmt.Println("Bip44:", base64.StdEncoding.EncodeToString(addr))

		//for i := 1; i <= 10; i++ {
		//	key, _ := km.GetKey(derivation.PurposeBIP44, CoinType, 0, 0, uint32(i))
		//	key.CreateAddr("TEST")
		//}
	})

}

//生成助记词
//助记词倒推出seed  调用NewWallet方法 初始化钱包
//助记词倒推出seed  key, code, err :=crypto.BuildKeyBySeed(&seedBs, Salt)
//keyNew, _, err = crypto.HkdfChainCodeNew(key, code, 0)
//checkHash := sha256.Sum256(*keyNew)
//子秘钥
//	var subKeySec []byte
//	subKeySec, err = crypto.EncryptCBC(*keyNew, newAddressPasswordB[:], Salt) //对子地址加密码 这里存进keystore
// 通过 km.GetKey(PurposeBIP44, CoinType, 0, 0, 0)倒推出公钥推出地址
//	addr := crypto.BuildAddr(this.AddrPre, puk)

//keyStore钱包结构 调用生成地址  公钥生成地址  分层推导出公钥==>对公钥有个密码验证
//然后生成地址公钥==>
//生成地址
