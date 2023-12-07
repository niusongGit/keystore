package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"gitee.com/prestonTao/utils"

	"golang.org/x/crypto/hkdf"
)

/*
	获取hkdf链编码
	@master    []byte    随机数
	@salt      []byte    盐
	@index     uint64    索引，棘轮数
*/
func GetHkdfChainCode(master, salt []byte, index uint64) (key, chainCode []byte, err error) {
	key, chainCode = master, salt
	for i := 0; i <= int(index); i++ {
		key, chainCode, err = hkdfChainCode(key, chainCode)
		if err != nil {
			return nil, nil, err
		}
		// fmt.Println("----", len(key), len(chainCode))
	}
	return
}

func hkdfChainCode(master, salt []byte) (key, chainCode []byte, err error) {
	hkdf := hkdf.New(sha256.New, master, salt, nil)
	keys := make([][]byte, 2)
	for i := 0; i < len(keys); i++ {
		keys[i] = make([]byte, 32)
		n, err := io.ReadFull(hkdf, keys[i])
		if n != len(keys[i]) {
			return nil, nil, errors.New("hkdf chain read hash fail")
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return keys[0], keys[1], nil
}

/*
	获取hkdf链编码
	@master    []byte    随机数
	@salt      []byte    盐
	@index     uint64    索引，棘轮数
*/
func HkdfChainCodeNew(master, salt []byte, index uint64) (*[]byte, *[]byte, error) {
	if index > 100 {
		return HkdfChainCodeNewV3(master, salt, index)
	}
	// fmt.Println("获取hkdf链编码:", hex.EncodeToString(master), hex.EncodeToString(salt), index)
	hkdf := hkdf.New(sha256.New, master, salt, nil)
	hashSeed := make([]byte, 64)
	for i := uint64(0); i < index; i++ {
		// fmt.Println("for获取hkdf链编码:", i)
		n, err := io.ReadFull(hkdf, hashSeed)
		if n != len(hashSeed) {
			fmt.Println("hkdf read error:", n)
			return nil, nil, errors.New("hkdf chain read hash fail")
		}
		if err != nil {
			return nil, nil, err
		}
	}

	key := hashSeed[:32]
	chainCode := hashSeed[32:]
	return &key, &chainCode, nil
}

/*
	获取hkdf链编码
	@master    []byte    随机数
	@salt      []byte    盐
	@index     uint64    索引，棘轮数
*/
func HkdfChainCodeNewV3(master, salt []byte, index uint64) (*[]byte, *[]byte, error) {
	// fmt.Println("获取hkdf链编码:", hex.EncodeToString(master), hex.EncodeToString(salt), index)

	hkdf := hkdf.New(sha256.New, master, salt, utils.Uint64ToBytes(index))
	hashSeed := make([]byte, 64)
	// fmt.Println("for获取hkdf链编码:", i)
	n, err := io.ReadFull(hkdf, hashSeed)
	if n != len(hashSeed) {
		// fmt.Println("hkdf read error:", n)
		return nil, nil, errors.New("hkdf chain read hash fail")
	}
	if err != nil {
		return nil, nil, err
	}

	key := hashSeed[:32]
	chainCode := hashSeed[32:]
	return &key, &chainCode, nil
}

/*
	通过种子生成key和chainCode
*/
func BuildKeyBySeed(seed *[]byte, salt []byte) (*[]byte, *[]byte, error) {
	hash := sha256.New

	key := [32]byte{}
	hkdf := hkdf.New(hash, *seed, salt, nil)
	_, err := io.ReadFull(hkdf, key[:])
	if err != nil {
		return nil, nil, err
	}
	code := [32]byte{}
	_, err = io.ReadFull(hkdf, code[:])
	if err != nil {
		return nil, nil, err
	}
	keyNew := key[:]
	codeNew := code[:]
	return &keyNew, &codeNew, nil
}
