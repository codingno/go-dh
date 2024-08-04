package godh

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

type DiffiHellman struct {
  PrivateKey *ecdh.PrivateKey
  PublicKey *ecdh.PublicKey
}

func NewDiffieHellman() *DiffiHellman {
  dh := ecdh.X25519()
  privateKey, err := dh.GenerateKey(rand.Reader)
  if err != nil {
    panic(err)
  }
  publicKey := privateKey.PublicKey()

  return &DiffiHellman{
    privateKey,
    publicKey,
  }
}

func (dh *DiffiHellman) SharedSecret(publicKeyString string) ([]byte, error){
  publicKeyByte, err := base64.StdEncoding.DecodeString(publicKeyString)
  if err != nil {
    return nil, err
  }
  publicKey, err := ecdh.X25519().NewPublicKey(publicKeyByte)
  if err != nil {
    return nil, err
  }

  return dh.PrivateKey.ECDH(publicKey)
}
