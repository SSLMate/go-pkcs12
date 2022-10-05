package pkcs12

import "crypto/cipher"

type noCipher struct{}

func (n noCipher) BlockSize() int {
	return 1
}
func (n noCipher) CryptBlocks(dst, src []byte) {
	copy(dst, src)
}

type streamToBlock struct {
	Stream cipher.Stream
}

func (c streamToBlock) BlockSize() int { return 1 }

func (c streamToBlock) CryptBlocks(dst, src []byte) {
	c.Stream.XORKeyStream(dst, src)
}
func (c streamToBlock) Decrypt(dst, src []byte) {
	c.Stream.XORKeyStream(dst, src)
}

func (c streamToBlock) Encrypt(dst, src []byte) {
	c.Stream.XORKeyStream(dst, src)
}
