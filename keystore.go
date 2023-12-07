package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"gitee.com/prestonTao/keystore/derivation"
	"io/ioutil"
	"sync"

	"gitee.com/prestonTao/keystore/crypto"
	"gitee.com/prestonTao/keystore/crypto/dh"
	"gitee.com/prestonTao/utils"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

const (
	MnemonicLang_cn = "cn" //简体中文
	MnemonicLang_en = "en" //英文
)

type KeystoreInterface interface {
	GetAddr() []*AddressInfo
	GetDHKeyPair() DHKeyPair
	CreateNetAddr(password, netAddressPassword string) (ed25519.PrivateKey, ed25519.PublicKey, error)
	GetNetAddr(pwd string) (ed25519.PrivateKey, ed25519.PublicKey, error)
	UpdateNetAddrPwd(oldpwd, newpwd string) (ok bool, err error)
	GetAddrAll() []*AddressInfo
	GetCoinbase() *AddressInfo
	FindAddress(addr crypto.AddressCoin) (addrInfo AddressInfo, ok bool)
	GetNewAddr(password, newAddressPassword string) (crypto.AddressCoin, error)
	GetKeyByAddr(addr crypto.AddressCoin, password string) (rand []byte, prk ed25519.PrivateKey, puk ed25519.PublicKey, err error)
	GetKeyByPuk(puk []byte, password string) (rand []byte, prk ed25519.PrivateKey, err error)
	GetPukByAddr(addr crypto.AddressCoin) (puk ed25519.PublicKey, ok bool)
	FindPuk(puk []byte) (addrInfo AddressInfo, ok bool)
	UpdatePwd(oldpwd, newpwd string) (ok bool, err error)
	UpdateAddrPwd(addr, oldpwd, newpwd string) (ok bool, err error)
	ImportMnemonic(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword string) error
	ExportMnemonic(pwd string) (string, error)
	GetFilePath() string
}

type Keystore struct {
	filepath      string             //keystore文件存放路径
	AddrPre       string             `json:"-"`        //
	Coinbase      uint64             `json:"coinbase"` //当前默认使用的收付款地址
	DHIndex       uint64             `json:"dhindex"`  //DH密钥，指向钱包位置
	lock          *sync.RWMutex      `json:"-"`        //
	MnemonicLang  []string           `json:"-"`
	Seed          []byte             `json:"seed"`      //种子
	CheckHash     []byte             `json:"checkhash"` //主私钥和链编码加密验证hash值
	Addrs         []*AddressInfo     `json:"addrs"`     //已经生成的地址列表
	DHKey         []DHKeyPair        `json:"dhkey"`     //DH密钥
	NetAddr       *NetAddrInfo       `json:"netaddr"`
	addrMap       *sync.Map          `json:"-"` //key:string=收款地址;value:*AddressInfo=地址密钥等信息;
	pukMap        *sync.Map          `json:"-"` //key:string=公钥;value:*AddressInfo=地址密钥等信息;
	netAddrPrkTmp ed25519.PrivateKey `json:"-"` //网络地址私钥
}

// 网络地址信息
type NetAddrInfo struct {
	Puk       ed25519.PublicKey `json:"puk"`       //公钥
	SubKey    []byte            `json:"subKey"`    //子密钥
	CheckHash []byte            `json:"checkhash"` //加密验证hash值
	Prkpwd    []byte            `json:"prkpwd"`    //私钥加密密码
}

func NewKeystore(filepath, addrPre string) *Keystore {
	keys := Keystore{
		filepath:     filepath,          //keystore文件存放路径
		AddrPre:      addrPre,           //
		lock:         new(sync.RWMutex), //
		MnemonicLang: wordlists.English, //
	}
	return &keys
}

/*
	NewKeyStoreTmpNetAddr
	@Description: 根据NetAddr私钥获取一个Keystore
	@param prk
	@return *Keystore
*/
func NewKeyStoreTmpNetAddr(prk []byte) *Keystore {
	return &Keystore{
		netAddrPrkTmp: ed25519.PrivateKey(prk),
	}
}

/*
	SetKeyStore
	@Description: 根据keystore文件设置Keystore对象
	@receiver this
	@param filepath 文件路径
	@param addrPre 地址前缀
	@return error
*/
func (this *Keystore) SetKeyStore(filepath, addrPre string) error {
	this.filepath = filepath
	this.AddrPre = addrPre
	this.lock = new(sync.RWMutex)
	this.MnemonicLang = wordlists.English
	return this.Load()
}
func (this *Keystore) GetFilePath() string {
	return this.filepath
}

/*
从磁盘文件加载keystore
*/
func (this *Keystore) Load() error {
	if err := RenameTempFile(this.filepath); err != nil {
		return err
	}

	bs, err := ioutil.ReadFile(this.filepath)
	if err != nil {
		return err
	}
	// fmt.Println(string(bs))

	// err = json.Unmarshal(bs, &this.Wallets)
	decoder := json.NewDecoder(bytes.NewBuffer(bs))
	decoder.UseNumber()
	err = decoder.Decode(&this)
	if err != nil {
		if err = this.oldKeystoreLoad(bs); err != nil {
			return err
		}
		return nil
	}
	this.lock = new(sync.RWMutex)
	this.addrMap = new(sync.Map)
	this.pukMap = new(sync.Map)
	if !this.CheckIntact() {

		return errors.New("Damaged wallet file: Wallet incomplete")
	}
	// if walletOne.Seed != nil && len(walletOne.Seed) > 0 {
	// 	walletOne.IV = salt
	// }
	// fmt.Println("地址个数=========", len(walletOne.Addrs))
	for j, one := range this.Addrs {
		addrInfo := this.Addrs[j]
		// addrStr := one.Addr.B58String()
		// addrInfo.AddrStr = addrStr
		//存在不是pib44协议地址时直接返回重新创建地址
		if addrInfo.Version != version_4 {
			this.Addrs = nil
			this.DHKey = nil
			return nil
		}

		this.addrMap.Store(utils.Bytes2string(one.Addr), addrInfo)
		this.pukMap.Store(utils.Bytes2string(one.Puk), addrInfo)
	}

	return nil
}

/*
	oldKeystoreLoad
	@Description: 旧版地址解析到新版地址并保存
	@receiver this
	@return error
*/
func (this *Keystore) oldKeystoreLoad(bs []byte) error {

	// err = json.Unmarshal(bs, &this.Wallets)
	decoder := json.NewDecoder(bytes.NewBuffer(bs))
	decoder.UseNumber()
	var wallets []*Keystore
	err := decoder.Decode(&wallets)
	if err != nil {
		return err
	}

	if len(wallets) <= 0 {
		//钱包文件损坏:钱包个数为0
		return errors.New("Damaged wallet file: the number of wallets is 0")
	}

	// TODO 这里只获取了第一个钱包
	this.Seed = wallets[0].Seed
	this.CheckHash = wallets[0].CheckHash
	//this.Coinbase = wallets[0].Coinbase
	//this.Addrs = make([]*AddressInfo, 0)
	//this.DHKey = make([]DHKeyPair, 0)
	this.lock = new(sync.RWMutex)
	this.addrMap = new(sync.Map)
	this.pukMap = new(sync.Map)
	if !this.CheckIntact() {
		//钱包文件损坏:第" + strconv.Itoa(i+1) + "个钱包不完整
		return errors.New("Damaged wallet file: Wallet incomplete")
	}

	/*for j, one := range this.Addrs {
		this.Addrs[j].SubKey = this.Seed
		this.Addrs[j].CheckHash = this.CheckHash
		addrInfo := this.Addrs[j]
		this.addrMap.Store(utils.Bytes2string(one.Addr), addrInfo)
		this.pukMap.Store(utils.Bytes2string(one.Puk), addrInfo)
	}*/

	err = this.Save()
	if err != nil {
		return nil
	}

	return nil
}

/*
检查钱包是否完整
*/
func (this *Keystore) CheckIntact() bool {
	if this.Seed != nil && len(this.Seed) > 0 {
		if this.CheckHash == nil || len(this.CheckHash) != 32 {
			// fmt.Println("111111111111========", len(this.CheckHash))
			return false
		}
		return true
	}
	if this.CheckHash == nil || len(this.CheckHash) != 64 {
		// fmt.Println("111111111111========", len(this.CheckHash))
		return false
	}

	return true
}

/*
从磁盘文件加载keystore
*/
func (this *Keystore) Save() error {
	bs, err := json.Marshal(this)
	if err != nil {
		return err
	}
	err = SaveFile(this.filepath, &bs)
	if err != nil {
		return errors.New("*********************保存keystore文件失败：" + err.Error())
	}

	return nil
}

/*
创建一个新的种子文件
*/
func (this *Keystore) CreateNewKeystore(password string) error {
	pwd := sha256.Sum256([]byte(password))

	seed, err := crypto.Rand16Byte() //随机生成16byte
	if err != nil {
		return err
	}
	seedBs := seed[:]
	err = this.NewWallet(&seedBs, &pwd)
	if err != nil {
		return err
	}
	//this.Version = version_3
	return nil
}

func (this *Keystore) NewWallet(seed *[]byte, pwd *[32]byte) error {

	seedSec, err := crypto.EncryptCBC(*seed, (*pwd)[:], Salt) //加密
	if err != nil {
		return err
	}

	checkHash := sha256.Sum256(*seed)

	this.Seed = seedSec //加密过后的
	this.CheckHash = checkHash[:]

	this.Addrs = make([]*AddressInfo, 0)
	this.Coinbase = 0
	this.DHKey = make([]DHKeyPair, 0)
	this.lock = new(sync.RWMutex)
	this.addrMap = new(sync.Map)
	this.pukMap = new(sync.Map)
	this.NetAddr = nil

	return nil
}

/*
使用随机数创建一个新的种子文件
*/
func (this *Keystore) CreateNewWalletRand(seedSrc []byte, password, firstCoinAddressPassword, netAddressAndDHkeyPassword string, coinAddrNum int) error {

	var err error
	pwd := sha256.Sum256([]byte(password))
	err = this.NewWallet(&seedSrc, &pwd)
	if err != nil {
		return err
	}
	if coinAddrNum > 1 {
		for i := 0; i < coinAddrNum; i++ {
			_, err = this.GetNewAddr(password, firstCoinAddressPassword)
			if err != nil {
				return err
			}
		}
	} else {
		_, err = this.GetNewAddr(password, firstCoinAddressPassword)
		if err != nil {
			return err
		}
	}
	_, err = this.GetNewDHKey(password, netAddressAndDHkeyPassword)
	if err != nil {
		return err
	}
	_, _, err = this.CreateNetAddr(password, netAddressAndDHkeyPassword)
	if err != nil {
		return err
	}
	return nil
}

func (this *Keystore) GetCoinbase() *AddressInfo {
	if this.Coinbase < uint64(len(this.Addrs)) {
		return this.Addrs[this.Coinbase]
	}
	return nil
}

/*
获取地址列表
*/
func (this *Keystore) GetAddr() (addrs []*AddressInfo) {
	this.lock.RLock()
	addrs = this.Addrs
	this.lock.RUnlock()
	return
}

/*
	GetNetAddrPwd
	@Description: 获取密码
	@receiver this
	@param prk
	@return string
	@return error
*/
func (this *Keystore) GetNetAddrPwd(prk []byte) (string, error) {
	if prk == nil || len(prk) == 0 {
		return "", errors.New("prk is empty")
	}
	pr := ed25519.PrivateKey(prk).Seed()
	p, err := crypto.DecryptCBC(this.NetAddr.Prkpwd, pr, Salt)
	if err != nil {
		return "", errors.New("prk is fail")
	}

	return string(p), nil
}

/*
	GetNetAddr
	@Description: 获取网络地址
	@receiver this
	@param password 网络地址的密码
	@return prk 地址私钥
	@return puk 地址公钥
	@return err
*/
func (this *Keystore) GetNetAddr(password string) (prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	//当密码为空时并且已经设置了Netaddr的私钥时直接通过私钥获取对应的公钥
	if password == "" && len(this.netAddrPrkTmp) > 0 {
		return this.getNetAddrTmp()
	}

	pwd := sha256.Sum256([]byte(password)) //网络地址的密码

	//先用密码解密种子
	subKeyBs, err := crypto.DecryptCBC(this.NetAddr.SubKey, pwd[:], Salt)
	if err != nil {
		return nil, nil, err
	}

	//判断密码是否正确
	chackHash := sha256.Sum256(subKeyBs)
	if !bytes.Equal(chackHash[:], this.NetAddr.CheckHash) {
		return nil, nil, ERROR_netAddr_password_fail
	}

	if this.NetAddr == nil {
		return nil, nil, ERROR_netaddr_empty
	}

	//获取秘钥
	puk, prk, err = ed25519.GenerateKey(bytes.NewBuffer(subKeyBs))
	if err != nil {
		return nil, nil, err
	}

	if this.NetAddr.Prkpwd == nil || len(this.NetAddr.Prkpwd) == 0 {
		this.lock.Lock()
		defer this.lock.Unlock()
		this.NetAddr.Prkpwd, err = crypto.EncryptCBC([]byte(password), prk.Seed(), Salt)
		if err != nil {
			return nil, nil, err
		}
		err = this.Save()
		if err != nil {
			return nil, nil, err
		}
	}

	return
}

/*
	CreateNetAddr
	@Description: 新建网络地址
	@receiver this
	@param password 钱包的密码
	@param netAddressPassword 网络地址的密码
	@return prk 地址私钥
	@return puk 地址公钥
	@return err
*/
func (this *Keystore) CreateNetAddr(password, netAddressPassword string) (prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	pwd := sha256.Sum256([]byte(password))                        //钱包的密码
	netAddrPasswordB := sha256.Sum256([]byte(netAddressPassword)) //网络地址的密码

	this.lock.Lock()
	defer this.lock.Unlock()

	//验证钱包密码是否正确
	_, keyRoot, codeRoot, err := this.Decrypt(pwd)
	if err != nil {
		return nil, nil, err
	}

	if this.NetAddr != nil {
		return nil, nil, ERROR_get_netaddr_errer
	}

	//通过原生seed 生成key和chainCode
	keyNew, _, err := crypto.HkdfChainCodeNew(keyRoot, codeRoot, 1) //兼容老版本地址index为1

	//生成子地址checkHash
	checkHash := sha256.Sum256(*keyNew)

	//子秘钥
	var subKeySec []byte
	subKeySec, err = crypto.EncryptCBC(*keyNew, netAddrPasswordB[:], Salt) //对子地址加密码
	if err != nil {
		return nil, nil, err
	}

	//获取秘钥
	puk, prk, err = ed25519.GenerateKey(bytes.NewBuffer(*keyNew))
	if err != nil {
		return nil, nil, err
	}

	prkPwd, err := crypto.EncryptCBC([]byte(netAddressPassword), prk.Seed(), Salt)
	if err != nil {
		return nil, nil, err
	}
	this.NetAddr = &NetAddrInfo{
		Puk:       puk,
		SubKey:    subKeySec,
		CheckHash: checkHash[:],
		Prkpwd:    prkPwd,
	}
	err = this.Save()
	if err != nil {
		return nil, nil, err
	}
	return
}

/*
获取DH公钥
*/
func (this *Keystore) GetDHKeyPair() DHKeyPair {
	/*wallet := this.Wallets[this.DHIndex]
	return wallet.GetDHbase()*/
	if len(this.DHKey) > 0 {
		return this.DHKey[len(this.DHKey)-1]
	}
	return DHKeyPair{}
}

/*
	GetNewDHKey
	@Description: 创建DHKey协商秘钥
	@receiver this
	@param password 钱包密码
	@param newDHKeyPassword DHKey密码
	@return *dh.KeyPair
	@return error
*/
func (this *Keystore) GetNewDHKey(password string, newDHKeyPassword string) (*dh.KeyPair, error) {
	pwd := sha256.Sum256([]byte(password))
	newDHKeyPasswordB := sha256.Sum256([]byte(newDHKeyPassword))
	this.lock.Lock()
	defer this.lock.Unlock()

	_, key, code, err := this.Decrypt(pwd)
	if err != nil {
		return nil, err
	}

	if this.DHKey != nil && len(this.DHKey) > 0 {
		return nil, ERROR_get_dhkey_errer
	}
	//查找用过的最高的棘轮数量
	//index := uint64(0)
	//if len(this.Addrs) > 0 {
	//	addrInfo := this.Addrs[len(this.Addrs)-1]
	//	index = addrInfo.Index
	//}
	//if len(this.DHKey) > 0 {
	//	dhKey := this.DHKey[len(this.DHKey)-1]
	//	if index < dhKey.Index {
	//		index = dhKey.Index
	//	}
	//}
	//index = index + 1
	//密码验证通过，生成新的地址
	var keyNew *[]byte

	// if this.Version == version_3 {
	// 	keyNew, _, err = crypto.HkdfChainCodeNewV3(key, code, index)
	// } else {
	index := uint64(2) //定死第二个为DHKey也兼容老版本
	keyNew, _, err = crypto.HkdfChainCodeNew(key, code, index)
	// }
	// keyNew, _, err := crypto.HkdfChainCodeNew(key, code, index)
	if err != nil {
		return nil, err
	}
	key = *keyNew

	//生成子地址checkHash
	checkHash := sha256.Sum256(key)

	//子秘钥
	var subKeySec []byte
	subKeySec, err = crypto.EncryptCBC(key, newDHKeyPasswordB[:], Salt)
	if err != nil {
		return nil, err
	}

	keyPair, err := dh.GenerateKeyPair(key)
	if err != nil {
		return nil, err
	}
	dhKey := DHKeyPair{
		Index:     index,
		KeyPair:   keyPair,
		CheckHash: checkHash[:],
		SubKey:    subKeySec,
	}
	this.DHKey = append(this.DHKey, dhKey)

	if err = this.Save(); err != nil {
		return nil, err
	}
	return &keyPair, nil
}

/*
获取地址列表，包括导入的钱包地址
*/
func (this *Keystore) GetAddrAll() []*AddressInfo {
	return this.GetAddr()
}

/*
钱包中查找地址，判断地址是否属于本钱包
*/
func (this *Keystore) FindAddress(addr crypto.AddressCoin) (addrInfo AddressInfo, ok bool) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	var v interface{}
	v, ok = this.addrMap.Load(utils.Bytes2string(addr))
	if !ok {
		return
	}
	addrInfo = *(v.(*AddressInfo))
	return
}

/*
	GetNewAddr
	@Description: 获取一个新的地址
	@receiver this
	@param password 钱包密码
	@param newAddressPassword 新地址密码
	@return crypto.AddressCoin
	@return error
*/
func (this *Keystore) GetNewAddr(password, newAddressPassword string) (crypto.AddressCoin, error) {
	pwd := sha256.Sum256([]byte(password))                           //钱包的密码
	newAddressPasswordB := sha256.Sum256([]byte(newAddressPassword)) //子地址的密码

	this.lock.Lock()
	defer this.lock.Unlock()

	//验证钱包密码是否正确
	_, _, _, err := this.Decrypt(pwd)
	if err != nil {
		return nil, err
	}
	//密码验证通过

	//查找用过的最高的棘轮数量
	index := uint64(0)
	if len(this.Addrs) > 0 {
		addrInfo := this.Addrs[len(this.Addrs)-1]
		index = addrInfo.Index + 1
		//	key = addrInfo.Key
		//	code = addrInfo.ChainCode
	}
	//dhIndex := uint64(0)
	//if len(this.DHKey) > 0 {
	//	dhKey := this.DHKey[len(this.DHKey)-1]
	//	dhIndex = dhKey.Index
	//}
	//index := addrIndex
	//if index < dhIndex {
	//	index = dhIndex
	//}
	//index = index + 1

	//var keyNew *[]byte
	//// if this.Version == version_3 {
	//// 	keyNew, _, err = crypto.HkdfChainCodeNewV3(keyRoot, codeRoot, index)
	//// } else {
	//
	////通过原生seed 生成key和chainCode
	//keyNew, _, err = crypto.HkdfChainCodeNew(keyRoot, codeRoot, index) //
	//// }
	//
	////生成子地址checkHash
	//checkHash := sha256.Sum256(*keyNew)
	//
	////子秘钥
	//var subKeySec []byte
	//subKeySec, err = crypto.EncryptCBC(*keyNew, newAddressPasswordB[:], Salt) //对子地址加密码
	//if err != nil {
	//	return nil, err
	//}

	//老版本start=====
	//获取公钥
	//buf := bytes.NewBuffer(*keyNew)
	//puk, _, err := ed25519.GenerateKey(buf)
	//if err != nil {
	//	return nil, err
	//}
	////根据公钥获取地址
	//addr := crypto.BuildAddr(this.AddrPre, puk)
	//老版本end=====

	//通过bip44推导出公钥.
	km, _ := derivation.GeneratePrivate(this.Seed, pwd[:], Salt, this.MnemonicLang)
	key, _ := km.GetKey(derivation.PurposeBIP44, derivation.CoinType, 0, 0, uint32(index)) //通过原生助记词推出私钥
	//根据私钥推导公钥生成地址.
	addr, puk, priks := key.CreateAddr(this.AddrPre)
	checkHash := sha256.Sum256(priks)
	subKeySec, err := crypto.EncryptCBC(priks, newAddressPasswordB[:], Salt) //对子地址加密码
	addrInfo := &AddressInfo{
		Index:     index, //棘轮数
		Addr:      addr,  //收款地址
		Puk:       puk,   //公钥
		CheckHash: checkHash[:],
		SubKey:    subKeySec,
		Version:   version_4, //地址版本
	}
	// fmt.Println("保存公钥", hex.EncodeToString(addrInfo.Puk), index)
	// fmt.Println("保存PUK", hex.EncodeToString(puk))
	this.Addrs = append(this.Addrs, addrInfo)
	this.addrMap.Store(utils.Bytes2string(addr), addrInfo)
	this.pukMap.Store(utils.Bytes2string(puk), addrInfo)
	if err = this.Save(); err != nil {
		return nil, err
	}
	return addr, err
}

/*
	Decrypt
	@Description: 使用钱包密码解密钱包种子，获得钱包私钥和链编码
	@receiver this
	@param pwdbs 钱包密码
	@return ok 密码是否正确
	@return key 生成私钥的随机数
	@return code 链编码
	@return err
*/
func (this *Keystore) Decrypt(pwdbs [32]byte) (bool, []byte, []byte, error) {
	//密码取hash

	//先用密码解密种子
	seedBs, err := crypto.DecryptCBC(this.Seed, pwdbs[:], Salt)
	if err != nil {
		return false, nil, nil, err
	}
	//判断密码是否正确
	chackHash := sha256.Sum256(seedBs)
	if !bytes.Equal(chackHash[:], this.CheckHash) {
		return false, nil, nil, ERROR_wallet_password_fail
	}

	key, code, err := crypto.BuildKeyBySeed(&seedBs, Salt)
	if err != nil {
		return false, nil, nil, err
	}

	return true, *key, *code, nil
}

/*
	GetNewAddrByName
	@Description: 获取一个新的地址,并且给新地址一个昵称
	@receiver this
	@param name 昵称
	@param password 钱包密码
	@param newAddressPassword 新地址密码
	@return crypto.AddressCoin
	@return error
*/
func (this *Keystore) GetNewAddrByName(name, password, newAddressPassword string) (crypto.AddressCoin, error) {
	addr, err := this.GetNewAddr(password, newAddressPassword)
	if err != nil {
		return addr, err
	}
	err = this.UpdateAddrName(name, newAddressPassword, addr)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

/*
	UpdateAddrName
	@Description: 修改地址的昵称
	@receiver this
	@param name 新昵称
	@param password 地址密码
	@param addr 地址
	@return error
*/
func (this *Keystore) UpdateAddrName(name, password string, addr crypto.AddressCoin) error {
	pwd := sha256.Sum256([]byte(password))

	this.lock.Lock()
	defer this.lock.Unlock()
	ok, _, err := this.AddrDecrypt(addr, pwd)
	if err != nil {
		return err
	}

	var v interface{}
	v, ok = this.addrMap.Load(utils.Bytes2string(addr))
	if !ok {
		return nil
	}
	addrInfo := v.(*AddressInfo)
	addrInfo.Nickname = name
	err = this.Save()
	return err
}

/*
	GetKeyByAddr
	@Description: 通过地址获取密钥对
	@receiver this
	@param addr 地址
	@param password 地址密码
	@return rand
	@return prk 地址私钥
	@return puk 地址公钥
	@return err
*/
func (this *Keystore) GetKeyByAddr(addr crypto.AddressCoin, password string) (rand []byte, prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	pwd := sha256.Sum256([]byte(password))
	this.lock.RLock()
	defer this.lock.RUnlock()

	ok, subKeyBs, err := this.AddrDecrypt(addr, pwd) //
	if err != nil {
		return nil, nil, nil, err
	}

	v, ok := this.addrMap.Load(utils.Bytes2string(addr))
	if !ok {
		return nil, nil, nil, ERROR_get_address_info_errer
	}
	addrInfo := v.(*AddressInfo)

	prk = subKeyBs //私钥
	puk = addrInfo.Puk
	return

}

/*
	AddrDecrypt
	@Description: 使用钱包地址密码解密钱包地址子秘钥
	@receiver this
	@param addr 地址
	@param pwdbs 地址密码
	@return ok 密码是否正确
	@return subKeyBs 子密私钥
	@return err
*/
func (this *Keystore) AddrDecrypt(addr crypto.AddressCoin, pwdbs [32]byte) (bool, []byte, error) {

	v, ok := this.addrMap.Load(utils.Bytes2string(addr))
	if !ok {
		return false, nil, ERROR_get_address_info_errer
	}
	addrInfo := v.(*AddressInfo)

	//先用密码解密种子
	subKeyBs, err := crypto.DecryptCBC(addrInfo.SubKey, pwdbs[:], Salt)
	if err != nil {
		return false, nil, err
	}

	//判断密码是否正确
	chackHash := sha256.Sum256(subKeyBs)
	if !bytes.Equal(chackHash[:], addrInfo.CheckHash) {
		return false, nil, ERROR_wallet_address_password_fail
	}

	/*key, code, err := crypto.BuildKeyBySeed(&subKeyBs, Salt)
	if err != nil {
		return false, nil, err
	}*/

	return true, subKeyBs, nil

}

/*
	GetKeyByPuk
	@Description: 通过公钥获取密钥
	@receiver this
	@param puk 地址公钥
	@param password 地址密码
	@return rand
	@return prk 地址私钥
	@return err
*/
func (this *Keystore) GetKeyByPuk(puk []byte, password string) (rand []byte, prk ed25519.PrivateKey, err error) {
	pwd := sha256.Sum256([]byte(password))
	this.lock.RLock()
	defer this.lock.RUnlock()

	v, ok := this.pukMap.Load(utils.Bytes2string(puk))
	if !ok {
		return nil, nil, ERROR_get_address_info_errer
	}
	addrInfo := v.(*AddressInfo)

	ok, subKeyBs, err := this.AddrDecrypt(addrInfo.Addr, pwd)
	if err != nil {
		return nil, nil, err
	}

	prk = subKeyBs //替换掉以前的私钥
	return
}

/*
通过地址获取公钥
*/
func (this *Keystore) GetPukByAddr(addr crypto.AddressCoin) (puk ed25519.PublicKey, ok bool) {
	this.lock.RLock()
	defer this.lock.RUnlock()

	var v interface{}
	v, ok = this.addrMap.Load(utils.Bytes2string(addr))
	if ok {
		puk = v.(*AddressInfo).Puk
	}
	return
}

/*
设置默认收付款地址
*/
func (this *Keystore) SetCoinbase(index uint64) bool {
	if index < uint64(len(this.Addrs)) {
		this.lock.Lock()
		this.Coinbase = uint64(index)
		this.lock.Unlock()
		return true
	}
	return false
}

/*
钱包中查找公钥是否存在
*/
func (this *Keystore) FindPuk(puk []byte) (addrInfo AddressInfo, ok bool) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	var v interface{}
	v, ok = this.pukMap.Load(utils.Bytes2string(puk))
	if !ok {
		return
	}
	addrInfo = *(v.(*AddressInfo))
	return
}

/*
修改钱包密码
*/
func (this *Keystore) UpdatePwd(oldpwd, newpwd string) (ok bool, err error) {
	oldHash := sha256.Sum256([]byte(oldpwd))
	newHash := sha256.Sum256([]byte(newpwd))
	this.lock.RLock()
	defer this.lock.RUnlock()

	ok, _, _, err = this.Decrypt(oldHash)
	if err != nil {
		return false, err
	}

	//先用密码解密种子
	seedBs, err := crypto.DecryptCBC(this.Seed, oldHash[:], Salt)
	if err != nil {
		return false, err
	}

	seedSec, err := crypto.EncryptCBC(seedBs, newHash[:], Salt)
	if err != nil {
		return false, err
	}

	checkHash := sha256.Sum256(seedBs)
	this.Seed = seedSec
	this.CheckHash = checkHash[:]

	err = this.Save()
	return true, err
}

/*
修改钱包子地址密码
*/
func (this *Keystore) UpdateAddrPwd(addr, oldpwd, newpwd string) (ok bool, err error) {
	addrCoin := crypto.AddressFromB58String(addr)
	oldHash := sha256.Sum256([]byte(oldpwd))
	newHash := sha256.Sum256([]byte(newpwd))
	this.lock.RLock()
	defer this.lock.RUnlock()

	var addrInfo *AddressInfo
	v, ok := this.addrMap.Load(utils.Bytes2string(addrCoin))
	if ok {
		addrInfo = v.(*AddressInfo)
	} else {
		return false, ERROR_get_address_info_errer
	}

	//旧密码解密子秘钥
	ok, subKeyBs, err := this.AddrDecrypt(addrCoin, oldHash)
	if err != nil {
		return false, err
	}

	//用新密码加密子秘钥
	subKeySec, err := crypto.EncryptCBC(subKeyBs, newHash[:], Salt)
	if err != nil {
		return false, err
	}

	addrInfo.SubKey = subKeySec
	checkHashArr := sha256.Sum256(subKeyBs)
	addrInfo.CheckHash = checkHashArr[:]
	err = this.Save()
	return true, err
}

/*
修改网络地址密码
*/
func (this *Keystore) UpdateNetAddrPwd(oldpwd, newpwd string) (ok bool, err error) {
	oldHash := sha256.Sum256([]byte(oldpwd))
	newHash := sha256.Sum256([]byte(newpwd))
	this.lock.RLock()
	defer this.lock.RUnlock()

	if this.NetAddr == nil {
		return false, ERROR_get_address_info_errer
	}

	//先用旧密码解密种子
	subKeyBs, err := crypto.DecryptCBC(this.NetAddr.SubKey, oldHash[:], Salt)
	if err != nil {
		return false, err
	}

	//判断密码是否正确
	chackHash := sha256.Sum256(subKeyBs)
	if !bytes.Equal(chackHash[:], this.NetAddr.CheckHash) {
		return false, ERROR_netAddr_password_fail
	}

	//用新密码加密子秘钥
	subKeySec, err := crypto.EncryptCBC(subKeyBs, newHash[:], Salt)
	if err != nil {
		return false, err
	}

	_, prk, err := ed25519.GenerateKey(bytes.NewBuffer(subKeyBs))
	if err != nil {
		return false, err
	}
	prkPwd, err := crypto.EncryptCBC([]byte(newpwd), prk.Seed(), Salt)
	if err != nil {
		return false, err
	}

	this.NetAddr.SubKey = subKeySec
	checkHashArr := sha256.Sum256(subKeyBs)
	this.NetAddr.CheckHash = checkHashArr[:]
	this.NetAddr.Prkpwd = prkPwd
	err = this.Save()
	return true, err
}

/*
	UpdateDHKeyPwd
	@Description: 修改DHKey密碼
	@receiver this
	@param index
	@param oldpwd 旧密码
	@param newpwd 新密码
	@return ok
	@return err
*/
func (this *Keystore) UpdateDHKeyPwd(oldpwd, newpwd string) (ok bool, err error) {
	oldHash := sha256.Sum256([]byte(oldpwd))
	newHash := sha256.Sum256([]byte(newpwd))
	this.lock.RLock()
	defer this.lock.RUnlock()

	//找到该索引的DHKey
	if len(this.DHKey) <= 0 || this.DHKey == nil {
		return false, ERROR_get_dhkey_errer
	}

	dhkey := &this.DHKey[len(this.DHKey)-1]

	if dhkey.SubKey == nil || len(dhkey.SubKey) == 0 {
		return false, ERROR_get_dhkey_errer
	}

	//先用旧密码解密种子
	subKeyBs, err := crypto.DecryptCBC(dhkey.SubKey, oldHash[:], Salt)
	if err != nil {
		return false, err
	}

	//判断密码是否正确
	chackHash := sha256.Sum256(subKeyBs)
	if !bytes.Equal(chackHash[:], dhkey.CheckHash) {
		return false, ERROR_DHKey_password_fail
	}

	//用新密码加密子秘钥
	subKeySec, err := crypto.EncryptCBC(subKeyBs, newHash[:], Salt)
	if err != nil {
		return false, err
	}

	dhkey.SubKey = subKeySec
	dhkey.CheckHash = chackHash[:]
	err = this.Save()
	return true, err
}

/*
签名
*/
func Sign(prk ed25519.PrivateKey, content []byte) []byte {
	if len(prk) == 0 {
		return nil
	}
	return ed25519.Sign(prk, content)
}

/*
设置助记词语言
*/
func (this *Keystore) SetLang(lan string) {
	if lan == MnemonicLang_cn {
		this.MnemonicLang = wordlists.ChineseSimplified
	}
	if lan == MnemonicLang_en {
		this.MnemonicLang = wordlists.English
	}
}

/*
	ExportMnemonic
	@Description: 导出助记词
	@receiver this
	@param pwd 钱包密码
	@return string 助词记
	@return error
*/
func (this *Keystore) ExportMnemonic(pwd string) (string, error) {
	pwdHash := sha256.Sum256([]byte(pwd))
	//先用密码解密种子
	seedBs, err := crypto.DecryptCBC(this.Seed, pwdHash[:], Salt)
	if err != nil {
		// fmt.Println("1111111111")
		return "", err
	}
	//判断密码是否正确
	chackHash := sha256.Sum256(seedBs)
	if !bytes.Equal(chackHash[:], this.CheckHash) {
		// fmt.Println("2222222222")
		return "", ERROR_wallet_password_fail
	}
	bip39.SetWordList(this.MnemonicLang)
	mn, err := bip39.NewMnemonic(seedBs)
	if err != nil {
		// fmt.Println("33333333333")
		return "", err
	}
	return mn, nil
}

/*
	ImportMnemonic
	@Description: 导入助记词
	@receiver this
	@param words 助记词
	@param pwd 钱包密码
	@param firstCoinAddressPassword 首个钱包地址的密码
	@param firstAddressPassword 首个网络地址和DHkey的密码
	@return error
*/
func (this *Keystore) ImportMnemonic(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword string) error {
	bip39.SetWordList(this.MnemonicLang)
	seedBs, err := bip39.EntropyFromMnemonic(words) //12位助记词  原生的seed 这个seed是没有加密过的
	if err != nil {
		return err
	}
	err = this.CreateNewWalletRand(seedBs, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword, 1)
	return err
}

/*
 	ImportMnemonicCreateMoreCoinAddr
 	@Description: 导入助记词生成多个钱包地址
 	@receiver this
 	@param words 助记词
	@param pwd 钱包密码
	@param firstCoinAddressPassword 首个钱包地址的密码
	@param firstAddressPassword 首个网络地址和DHkey的密码
 	@param coinAddrNum 创建多少个钱包地址
 	@return error
*/
func (this *Keystore) ImportMnemonicCreateMoreCoinAddr(words, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword string, coinAddrNum int) error {
	bip39.SetWordList(this.MnemonicLang)
	seedBs, err := bip39.EntropyFromMnemonic(words) //12位助记词  原生的seed 这个seed是没有加密过的
	if err != nil {
		return err
	}
	err = this.CreateNewWalletRand(seedBs, pwd, firstCoinAddressPassword, netAddressAndDHkeyPassword, coinAddrNum)
	return err
}

/*
	getNetAddrTmp
	@Description: 根据NetAddr私钥推导公钥
	@receiver this
	@return ed25519.PrivateKey
	@return ed25519.PublicKey
	@return error
*/
func (this *Keystore) getNetAddrTmp() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, ok := this.netAddrPrkTmp.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("根据私钥推导公钥失败!!!!")
	}
	return this.netAddrPrkTmp, pub, nil
}

/*
	GetNetAddrKeyByMnemonic
	@Description: 根据助记词获取网络地址公私钥
	@param words 助记词
	@param mnemonicLang 助记词版本
	@return prk
	@return puk
	@return err
*/
func GetNetAddrKeyByMnemonic(words string, mnemonicLang []string) (prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	bip39.SetWordList(mnemonicLang)
	seedBs, err := bip39.EntropyFromMnemonic(words) //12位助记词  原生的seed 这个seed是没有加密过的
	if err != nil {
		return nil, nil, err
	}
	keyRoot, codeRoot, err := crypto.BuildKeyBySeed(&seedBs, Salt)
	if err != nil {
		return nil, nil, err
	}

	//通过原生seed 生成key和chainCode
	keyNew, _, err := crypto.HkdfChainCodeNew(*keyRoot, *codeRoot, 1) //兼容老版本地址index为1

	//获取秘钥
	puk, prk, err = ed25519.GenerateKey(bytes.NewBuffer(*keyNew))
	if err != nil {
		return nil, nil, err
	}
	return
}
