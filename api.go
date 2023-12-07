package keystore

import (
	"fmt"

	"gitee.com/prestonTao/keystore/crypto"
	"golang.org/x/crypto/ed25519"
)

var keystoreStatic *Keystore

/*
加载种子
*/
func Load(fileAbsPath, addrPre string) error {
	// addrPreStatic = addrPre
	store := NewKeystore(fileAbsPath, addrPre)
	err := store.Load()
	if err != nil {
		return err
	}
	keystoreStatic = store
	return nil
}

/*
	CreateKeystore
	@Description: 创建一个新的keystore
	@param fileAbsPath
	@param addrPre
	@param password 钱包密码
	@return error
*/
func CreateKeystore(fileAbsPath, addrPre, password string) error {
	ks := NewKeystore(fileAbsPath, addrPre)
	err := ks.CreateNewKeystore(password)
	if err != nil {
		return err
	}
	err = ks.Save()
	if err != nil {
		return err
	}
	keystoreStatic = ks
	return nil
}

/*
	CreateKeystoreRand
	@Description: 使用随机数创建一个新的keystore
	@param fileAbsPath
	@param addrPre
	@param seed
	@param rand1
	@param rand2
	@param password 钱包密码
	@param firstCoinAddressPassword 首个钱包地址的密码
	@param firstAddressPassword 首个网络地址和DHkey的密码
	@return error
*/
func CreateKeystoreRand(fileAbsPath, addrPre string, seed []byte, password, firstCoinAddressPassword, netAddressAndDHkeyPassword string) error {
	ks := NewKeystore(fileAbsPath, addrPre)
	err := ks.CreateNewWalletRand(seed, password, firstCoinAddressPassword, netAddressAndDHkeyPassword, 1)
	if err != nil {
		return err
	}
	err = ks.Save()
	if err != nil {
		return err
	}
	keystoreStatic = ks
	return nil
}

// //设置新的种子
// func NewLoad(seed, password string) error {
// 	pass := md5.Sum([]byte(password))
// 	seedData, err := Encrypt([]byte(seed), pass[:])
// 	if err != nil {
// 		return err
// 	}
// 	seeds := Seed{Data: seedData}
// 	NWallet.SetSeed(seeds)
// 	NWallet.SaveSeed(NWallet.Seeds)
// 	NWallet.SetSeedIndex(0)
// 	//创建矿工地址
// 	NWallet.GetNewAddress(pass[:])
// 	return nil
// }

/*
获取钱包地址列表，不包括导入的钱包地址
*/
func GetAddr() []*AddressInfo {
	return keystoreStatic.GetAddr()
}

/*
	GetNetAddr
	@Description: 获取本钱包的网络地址
	@param pwd 网络地址的密码
	@return ed25519.PrivateKey 地址私钥
	@return ed25519.PublicKey 地址公钥
	@return error
*/
func GetNetAddr(pwd string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	return keystoreStatic.GetNetAddr(pwd)
}

/*
	GetNewNetAddr
	@Description: 新建网络地址
	@param pwd 网络地址的密码
	@return ed25519.PrivateKey 地址私钥
	@return ed25519.PublicKey 地址公钥
	@return error
*/
func CreateNetAddr(password, netAddressPassword string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	return keystoreStatic.CreateNetAddr(password, netAddressPassword)
}

/*
获取地址列表，包括导入的钱包地址
*/
func GetAddrAll() []*AddressInfo {
	return keystoreStatic.GetAddrAll()
}

/*
	GetNewAddr
	@Description: 获取一个新的地址
	@param password 钱包密码
	@param newAddressPassword 新地址密码
	@return crypto.AddressCoin
	@return error
*/
func GetNewAddr(password, newAddressPassword string) (crypto.AddressCoin, error) {
	addrCoin, err := keystoreStatic.GetNewAddr(password, newAddressPassword)
	if err != nil {
		return nil, err
	}
	return addrCoin, err
}

/*
	GetNewAddrByName
	@Description: 获取一个新的地址,并且给新地址一个昵称
	@param name
	@param password 钱包密码
	@param newAddressPassword 新地址密码
	@return crypto.AddressCoin
	@return error
*/
func GetNewAddrByName(name, password, newAddressPassword string) (crypto.AddressCoin, error) {
	return keystoreStatic.GetNewAddrByName(name, password, newAddressPassword)
}

/*
	UpdateAddrName
	@Description: 修改一个地址的昵称
	@param name
	@param password 地址密码
	@param addr
	@return error
*/
func UpdateAddrName(name, password string, addr crypto.AddressCoin) error {
	return keystoreStatic.UpdateAddrName(name, password, addr)
}

// 获取基础地址
func GetCoinbase() *AddressInfo {
	return keystoreStatic.GetCoinbase()
}

/*
获取DH公钥
*/
func GetDHKeyPair() DHKeyPair {
	return keystoreStatic.GetDHKeyPair()
}

/*
	GetKeyByAddr
	@Description: 通过地址获取密钥对
	@param addr
	@param password 地址密码
	@return rand
	@return prk 地址私钥
	@return puk 地址公钥
	@return err
*/
func GetKeyByAddr(addr crypto.AddressCoin, password string) (rand []byte, prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	return keystoreStatic.GetKeyByAddr(addr, password)
}

/*
	GetKeyByPuk
	@Description: 通过公钥获取密钥
	@param puk 地址公钥
	@param password 地址密码
	@return rand
	@return prk 地址私钥
	@return err
*/
func GetKeyByPuk(puk []byte, password string) (rand []byte, prk ed25519.PrivateKey, err error) {
	return keystoreStatic.GetKeyByPuk(puk, password)
}

/*
	GetPukByAddr
	@Description: 通过地址获取公钥
	@param addr
	@return puk 地址公钥
	@return ok
*/
func GetPukByAddr(addr crypto.AddressCoin) (puk ed25519.PublicKey, ok bool) {
	return keystoreStatic.GetPukByAddr(addr)
}

// 设置基础地址
func SetCoinbase(index int) {
	// NWallet.SetCoinbase(index)
	keystoreStatic.SetCoinbase(uint64(index))
}

/*
钱包中查找地址，判断地址是否属于本钱包
*/
func FindAddress(addr crypto.AddressCoin) (addrInfo AddressInfo, ok bool) {
	return keystoreStatic.FindAddress(addr)
}

/*
钱包中查找公钥是否存在
*/
func FindPuk(puk []byte) (addrInfo AddressInfo, ok bool) {
	return keystoreStatic.FindPuk(puk)
}

/*
修改钱包密码
*/
func UpdatePwd(oldpwd, newpwd string) (ok bool, err error) {
	return keystoreStatic.UpdatePwd(oldpwd, newpwd)
}

/*
	UpdateAddrPwd
	@Description: 修改钱包地址密码
	@param addr
	@param oldpwd 地址旧密码
	@param newpwd 地址新密码
	@return ok
	@return err
*/
func UpdateAddrPwd(addr, oldpwd, newpwd string) (ok bool, err error) {
	return keystoreStatic.UpdateAddrPwd(addr, oldpwd, newpwd)
}

/*
	UpdateAddrPwd
	@Description: 修改网络地址密码
	@param addr
	@param oldpwd 地址旧密码
	@param newpwd 地址新密码
	@return ok
	@return err
*/
func UpdateNetAddrPwd(oldpwd, newpwd string) (ok bool, err error) {
	return keystoreStatic.UpdateNetAddrPwd(oldpwd, newpwd)
}

/*
	UpdateDHKeyPwd
	@Description: 修改DHKey密码
	@param oldpwd 旧密码
	@param newpwd 新密码
	@return ok
	@return err
*/
func UpdateDHKeyPwd(oldpwd, newpwd string) (ok bool, err error) {
	return keystoreStatic.UpdateDHKeyPwd(oldpwd, newpwd)
}

/*
	ExportMnemonic
	@Description: 导出助记词
	@param pwd 钱包密码
	@return string 助记词
	@return error
*/
func ExportMnemonic(pwd string) (string, error) {
	return keystoreStatic.ExportMnemonic(pwd)
}

/*
	ImportMnemonic
	@Description: 导入助记词
	@param words 助记词
	@param pwd 钱包密码
	@param firstCoinAddressPassword 首个钱包地址的密码
	@param firstAddressPassword 首个网络地址和DHkey的密码
	@return error
*/
func ImportMnemonic(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword string) error {
	err := keystoreStatic.ImportMnemonic(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword)
	if err != nil {
		return err
	}
	return nil
}

/*
	ImportMnemonicCreateMoreCoinAddr
	@Description: 导入助记词生成多个钱包地址
	@param words 助记词
	@param pwd 钱包密码
	@param firstCoinAddressPassword 首个钱包地址的密码
	@param firstAddressPassword 首个网络地址和DHkey的密码
	@param coinAddrNum 创建多少个钱包地址
	@return error
*/
func ImportMnemonicCreateMoreCoinAddr(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword string, coinAddrNum int) error {
	err := keystoreStatic.ImportMnemonicCreateMoreCoinAddr(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword, coinAddrNum)
	if err != nil {
		return err
	}
	return nil
}

//根据地址获取私钥
// func GetPriKeyByAddress(address, password string) (prikey *ecdsa.PrivateKey, err error) {
// 	// pass := md5.Sum([]byte(password))
// 	// prikey, err = NWallet.GetPriKey(address, pass[:])
// 	// return
// }

//验证地址合法性(Address类型)
// func ValidateAddress(address *crypto.Address) bool {
// 	// validate = NWallet.ValidateAddress(address)
// 	// return
// 	return false
// }

//验证地址合法性(Addres类型)
// func ValidateByAddress(address string) bool {
// 	// validate = NWallet.ValidateByAddress(address)
// 	// return
// 	return false
// }

//获取某个地址的扩展地址
// func GetNewExpAddr(preAddress *Address) *utils.Multihash {
// 	// addr := NWallet.GetNewExpAddress(preAddress)
// 	// return addr
// }

//根据公钥生成地址multihash
// func BuildAddrByPubkey(pub []byte) (*utils.Multihash, error) {
// 	// addr, err := buildAddrinfo(pub, Version)
// 	// return addr, err
// }

func Println() {
	bs, _ := json.Marshal(keystoreStatic)

	fmt.Println("keystore\n", string(bs))
}

//export keystore
func GetKeyStore() *Keystore {
	return keystoreStatic
}
