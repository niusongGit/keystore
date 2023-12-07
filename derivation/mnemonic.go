package derivation

import "github.com/tyler-smith/go-bip39"

func CreateMnemonic(bitSize int) (string, error) {
	entropy, err := bip39.NewEntropy(bitSize) //128 12位 256 24位.
	if err != nil {
		return "", err
	}
	Mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return Mnemonic, nil
}
