package keystore

import (
	"encoding/hex"
	"gitee.com/prestonTao/keystore/crypto"
	"gitee.com/prestonTao/keystore/crypto/dh"
	"golang.org/x/crypto/ed25519"
)

// var Salt = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07} //加密盐
var Salt = []byte{53, 111, 103, 103, 87, 66, 54, 103, 53, 108, 65, 81, 73, 53, 70, 43} //加密盐
const (
	version_4 = 4
	version_5 = 5
)

type AddressInfo struct {
	Index     uint64             `json:"index"`     //棘轮数量
	Nickname  string             `json:"nickname"`  //地址昵称
	Addr      crypto.AddressCoin `json:"addr"`      //收款地址
	puk       ed25519.PublicKey  `json:"puk"`       //未加密公钥
	CPuk      []byte             `json:"cpuk"`      //加密公钥
	SubKey    []byte             `json:"subKey"`    //子密钥
	AddrStr   string             `json:"-"`         //
	PukStr    string             `json:"-"`         //
	CheckHash []byte             `json:"checkhash"` //主私钥和链编码加密验证hash值
	//	Version   int                `json:"version"`   //地址版本
}

func (this *AddressInfo) GetAddrStr() string {
	if this.AddrStr == "" {
		this.AddrStr = this.Addr.B58String()
	}
	return this.AddrStr
}

func (this *AddressInfo) GetPukStr() string {
	if this.PukStr == "" || this.puk == nil {
		this.PukStr = hex.EncodeToString(this.puk)
	}
	return this.PukStr
}

type DHKeyPair struct {
	Index     uint64     `json:"index"`     //棘轮数量
	KeyPair   dh.KeyPair `json:"keypair"`   //
	CheckHash []byte     `json:"checkhash"` //主私钥和链编码加密验证hash值
	SubKey    []byte     `json:"subKey"`    //子密钥
}
