package godh_test

import (
	"encoding/base64"
	godh "go-dh"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiffieHellmanSharedSecret(t *testing.T) {
  dh := godh.NewDiffieHellman()
  dh2 := godh.NewDiffieHellman()

  publicKey1 := base64.StdEncoding.EncodeToString(dh.PublicKey.Bytes())
  publicKey2 := base64.StdEncoding.EncodeToString(dh2.PublicKey.Bytes())

  ecdh1, err := dh.SharedSecret(publicKey2)
  require.NoError(t, err, "Error when process SharedSecret1")
  ecdh2, err := dh2.SharedSecret(publicKey1)
  require.NoError(t, err, "Error when process SharedSecret2")

  sharedSecret1 := base64.StdEncoding.EncodeToString(ecdh1)
  sharedSecret2 := base64.StdEncoding.EncodeToString(ecdh2)

  require.Equal(t, sharedSecret1, sharedSecret2, "Error shared secret not equal")

}
