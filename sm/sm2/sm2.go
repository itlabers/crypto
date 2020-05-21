package sm2

import (
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"hash"
	"io"
	"math/big"

	"github.com/itlabers/crypto/sm/sm3"
)

// PublicKey represents an sm2 public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents an sm2 private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

type sm2Signature struct {
	R, S *big.Int
}

// Sign generates signature for the input message using the private key and id.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hashFun := opts.HashFunc()
	var hash hash.Hash
	if hashFun.Available() {
		hash = hashFun.New()
	} else {
		hash = sm3.New()
	}
	r, s, error := Sign(rand, priv, DEFAULT_ID, digest, hash)
	if error != nil {
		return nil, err
	}  
	return asn1.Marshal(sm2Signature{r, s})
	
}

// Verify checks whether the input (r, s) is a valid signature for the message.
func (pub *PublicKey) Verify(msg []byte, hasher hash.Hash, r, s *big.Int) bool {
	N := pub.Params().N
	if N.Sign() == 0 {
		return false
	}
	mz, err := getZ(msg, pub, DEFAULT_ID, hasher)
	if err != nil {
		return false
	}
	hasher.Reset()
	hasher.Write(mz)
	digest := hasher.Sum(nil)
	return verify(pub, digest, r, s)
}

// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	pri := new(PrivateKey)
	pri.PublicKey.Curve = c
	pri.D = k
	pri.PublicKey.X, pri.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return pri, nil
}
