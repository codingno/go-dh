package godh

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

type PublicKey struct {
  *ecdh.PublicKey
}

type PrivateKey struct {
  *ecdh.PrivateKey
}

type DiffiHellman struct {
  PrivateKey *PrivateKey
  PublicKey *PublicKey
}

func NewDiffieHellman() *DiffiHellman {

  dh := ecdh.X25519()
  privateKey, err := dh.GenerateKey(rand.Reader)
  if err != nil {
    panic(err)
  }
  publicKey := privateKey.PublicKey()

  return &DiffiHellman{
    &PrivateKey{privateKey},
    &PublicKey{publicKey},
  }
}

func (dh *DiffiHellman) SharedSecret(publicKeyByte []byte) ([]byte, error){

  publicKey, err := NewPublicKey(publicKeyByte)
  if err != nil {
    return nil, err
  }

  return dh.PrivateKey.ECDH(publicKey.PublicKey)
}

func NewPublicKey(publicKeyByte []byte) (*PublicKey, error) {

  publicKey, err := ecdh.X25519().NewPublicKey(publicKeyByte)
  return &PublicKey{publicKey}, err
}

func (p *PublicKey) ToString() (string) {
  return base64.StdEncoding.EncodeToString(p.Bytes())
}

func (p *PrivateKey) ToString() (string) {
  return base64.StdEncoding.EncodeToString(p.Bytes())
}
