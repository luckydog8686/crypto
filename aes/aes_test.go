package aes

import "testing"

func TestEncrypt(t *testing.T) {
	pass := []byte("helloworld")
	str := "fuckyou bitch"
	enc,err:=Encrypt(str,pass)
	if err!= nil {
		t.Fatal(err)
	}
	t.Log("enc::",enc)
	dec,err := Decrypt(enc,pass)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("dec::",dec)
}