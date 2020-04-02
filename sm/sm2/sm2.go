package sm2

import (
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"io"
	"math/big"
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

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	r, s, err := Sign(rand, priv, DEFAULT_ID, digest, opts.HashFunc().New())
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
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
