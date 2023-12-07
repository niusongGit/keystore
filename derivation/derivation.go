package derivation

import (
	"crypto/ed25519"
	"fmt"
	"gitee.com/prestonTao/keystore/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"sync"
)

const (
	Zero         uint32 = 0
	ZeroQuote    uint32 = 0x80000000
	PurposeBIP44 uint32 = 0x8000002C // 44' BIP44
	PurposeBIP49 uint32 = 0x80000031 // 49' BIP49
	PurposeBIP84 uint32 = 0x80000054 // 84' BIP84
	Apostrophe   uint32 = 0x80000000
	CoinType     uint32 = 98055361
)

type KeyManager struct {
	mnemonic   string
	passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

type BipKey struct {
	path     string
	Bip32Key *bip32.Key
}

func NewKeyManager(mnemonic string, passphrase string) (*KeyManager, error) {
	km := &KeyManager{
		mnemonic:   mnemonic,
		passphrase: passphrase,
		keys:       make(map[string]*bip32.Key, 0),
	}
	return km, nil
}

// GeneratePrivate 根据原始seed推导私钥 123  1234
func GeneratePrivate(Seeds []byte, pbkdf2Key []byte, MnemonicLang []string) (*KeyManager, error) {

	newSeed, err := crypto.DecryptCBCPbkdf2Key(Seeds, pbkdf2Key) //通过keystore的加密后的seed解出原始的seed

	bip39.SetWordList(MnemonicLang)
	//fmt.Println("导入seed", newSeed)
	Mnemonic, _ := bip39.NewMnemonic(newSeed) //通过原生的seed推出助记词
	//fmt.Println("Mnemonic", Mnemonic)
	km, err := NewKeyManager(Mnemonic, "") //助记词的密码
	return km, err
}

// CreateAddr 通过助记词推导出私钥，再通过私钥生成地址
func (k *BipKey) CreateAddr(AddrPre string) (crypto.AddressCoin, ed25519.PublicKey, ed25519.PrivateKey) {
	privk := ed25519.NewKeyFromSeed(k.Bip32Key.Key) //私钥
	pub := privk.Public().(ed25519.PublicKey)
	addr := crypto.BuildAddr(AddrPre, pub) //公钥生成地址
	return addr, pub, privk

}

// GetKey  KeyManager 兼容一下批量创建的时候
func (km *KeyManager) GetKey(purpose, coinType, account, change, index uint32) (*BipKey, error) {

	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change, index)
	//fmt.Println(path)
	key, ok := km.getKey(path)
	if ok {
		return &BipKey{path: path, Bip32Key: key}, nil
	}

	parent, err := km.GetChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return &BipKey{path: path, Bip32Key: key}, nil
}

// GetChangeKey 获取指定路径的bip32.key
func (km *KeyManager) GetChangeKey(purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetAccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

// GetAccountKey 根据account获取key
func (km *KeyManager) GetAccountKey(purpose, coinType, account uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe, account)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetCoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(account + Apostrophe)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

// GetCoinTypeKey 根据不同币种获取key
func (km *KeyManager) GetCoinTypeKey(purpose, coinType uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetPurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(coinType)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

// GetPurposeKey 根据协议获取key
func (km *KeyManager) GetPurposeKey(purpose uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'`, purpose-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetMasterKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(purpose)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

// GetMasterKey 找根key
func (km *KeyManager) GetMasterKey() (*bip32.Key, error) {
	path := "m"
	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}
	key, err := bip32.NewMasterKey(km.GetSeed())
	if err != nil {
		return nil, err
	}
	km.setKey(path, key)
	return key, nil
}

// GetSeed 获取助记词的seed
func (km *KeyManager) GetSeed() []byte {
	return bip39.NewSeed(km.GetMnemonic(), km.GetPassphrase())
}

// 找根私钥 返构造bip32.key
func (km *KeyManager) getKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()
	key, ok := km.keys[path]
	return key, ok
}

// GetMnemonic 构造助记词返回
func (km *KeyManager) GetMnemonic() string {
	return km.mnemonic
}

// GetPassphrase 构造助记词密码返回
func (km *KeyManager) GetPassphrase() string {
	return km.passphrase
}

// 构造对应路径的key
func (km *KeyManager) setKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()
	km.keys[path] = key
}
