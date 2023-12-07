package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"gitee.com/prestonTao/keystore/base58"
	"golang.org/x/crypto/ed25519"
)

func TestAddr(t *testing.T) {
	// BuildAddrExample()
	//ParseAddr()
	ParseAddrPrefixTest()
}

func ParseAddr() {
	addStr := "SELFKN1RzSSzNQ9KdC3rH255SKp"
	addr := AddressFromB58String(addStr)
	fmt.Println(addr.B58String())
}

func BuildAddrExample() {
	puk, _, _ := ed25519.GenerateKey(rand.Reader)
	preStr := "TEST"
	addr := BuildAddr(preStr, puk)
	addrStr := base58.Encode(addr)
	fmt.Println(string(addrStr))

	ok := ValidAddr(preStr, addr)
	fmt.Println("验证是否通过", ok)
}

func ParseAddrPrefixTest() {
	addr := AddressFromB58String("TEST6d7g4uwGdeKF226zijoQKxE3BEMw7Nzqh5")
	//tmp := []byte(addr)
	ParseAddrPrefix(addr)
}
