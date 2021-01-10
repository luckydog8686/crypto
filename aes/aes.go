package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
)

func Encrypt(content string,pass []byte) (string, error) {
	aesPass :=GetPass(pass)
	block, err := aes.NewCipher(aesPass)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}
	blocksize := block.BlockSize()
	rawData := PKCS7Padding([]byte(content), blocksize)

	cipherText := make([]byte, blocksize+len(rawData))
	iv := cipherText[:blocksize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println(err.Error())
		return "", nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blocksize:], rawData)
	return hex.EncodeToString(cipherText), nil
}

func Decrypt(encryptedContent string,pass []byte)(string, error)  {
	aesPass :=GetPass(pass)
	block, err := aes.NewCipher(aesPass)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}
	encryptByte, err := hex.DecodeString(encryptedContent)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}
	blocksize := block.BlockSize()
	log.Println("blocksize ::", blocksize)
	if len(encryptByte) < blocksize {
		return "", errors.New("cipher text is too short" + string(encryptByte))
	}
	if len(encryptByte)%blocksize != 0 {
		return "", errors.New("密文长度不是blocksize的整数倍")
	}
	iv := encryptByte[:blocksize]
	encryptData := encryptByte[blocksize:]
	//log.Println("encryptData:::", hex.EncodeToString(encryptData))
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptData := make([]byte, len(encryptData))
	mode.CryptBlocks(encryptData, encryptData)
	//log.Println("unpadding前的数据：", hex.EncodeToString(encryptData))
	decryptData = PKCS7UnPadding(encryptData)
	return string(decryptData), nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func GetPass(pass []byte) []byte {

	aesPass := make([]byte, 0)
	md5hash := md5.Sum([]byte(pass))
	passLen := len(md5hash)
	for i := 0; i < passLen; i++ {
		aesPass = append(aesPass, md5hash[i])
	}
	return aesPass
}