package rsa

import "testing"

func TestGenerateKey(t *testing.T) {
	priv,pub,err:=GenerateKey()
	if err !=nil{
		t.Fatal(err)
	}
	t.Log(string(priv))
	t.Log(string(pub))
	privkey,err :=GetPrivKeyFromPem(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(privkey.D.String())
	pubKey,err :=GetPubKeyFromPem(pub)
	if err !=nil{
		t.Fatal(err)
	}
	t.Log(pubKey.N.String())
}