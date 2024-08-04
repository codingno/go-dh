package godh_test

import (
	godh "go-dh"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiffieHellmanSharedSecret(t *testing.T) {
  dh := godh.NewDiffieHellman()
  dh2 := godh.NewDiffieHellman()

  ecdh1, err := dh.SharedSecret(dh2.PublicKey.Bytes())
  require.NoError(t, err, "Error when process SharedSecret1")
  ecdh2, err := dh2.SharedSecret(dh.PublicKey.Bytes())
  require.NoError(t, err, "Error when process SharedSecret2")

  require.Equal(t, ecdh1, ecdh2, "Error shared secret not equal")
}
