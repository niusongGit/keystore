package derivation

import (
	"bytes"
	btcutil "github.com/FactomProject/btcutilecc"
	"math/big"
)

const PublicKeyCompressedLength = 33

var (
	curve = btcutil.Secp256k1()
)

//PublicKeyForPrivateKey 私钥转公钥
func PublicKeyForPrivateKey(key []byte) []byte {
	return compressPublicKey(curve.ScalarBaseMult(key))
}
func compressPublicKey(x *big.Int, y *big.Int) []byte {
	var key bytes.Buffer

	// 写入标头；0x2表示偶数y值；0x3表示奇数
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))

	// 写X坐标；按键盘，使x与LSB对齐。填充大小是密钥长度-标头大小（1）-xBytes大小
	xBytes := x.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)

	return key.Bytes()
}
