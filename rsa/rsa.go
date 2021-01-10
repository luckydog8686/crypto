package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func Sha256hash(message []byte) []byte {
	hash256 := sha256.Sum256(message)
	return hash256[:]
}

func Sign(privatekey *rsa.PrivateKey,hashed []byte)([]byte,error)  {
	return rsa.SignPKCS1v15(rand.Reader,privatekey,crypto.SHA256,hashed[:])
}

func Verify(publicKey *rsa.PublicKey,hashed,signature []byte)error{
	return rsa.VerifyPKCS1v15(publicKey,crypto.SHA256,hashed[:],signature)
}
func GenerateKey() ([]byte,[]byte,error){
	privateKey,err := rsa.GenerateKey(rand.Reader,2048)
	if err != nil {
		return nil,nil,err
	}
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privPem:=pem.EncodeToMemory(privBlock)

	publicKey :=  &privateKey.PublicKey
	publicBytes,err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil,nil,err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes:publicBytes,
	}
	pubPem := pem.EncodeToMemory(pubBlock)
	return privPem,pubPem,nil
}

func GetPubKeyFromPem(pubPem []byte) (*rsa.PublicKey,error) {
	block,_ := pem.Decode(pubPem)
	pubByte := block.Bytes
	pub,err := x509.ParsePKIXPublicKey(pubByte)
	if err != nil {
		return nil,err
	}
	publicKey,ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil,errors.New("failed to 转换成公钥")
	}
	return publicKey,nil

}
func GetPrivKeyFromPem(priPem []byte)(*rsa.PrivateKey,error)  {
	block,_ := pem.Decode(priPem)
	privByte := block.Bytes
	return x509.ParsePKCS1PrivateKey(privByte)
}
