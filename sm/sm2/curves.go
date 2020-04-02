package sm2

import (
	"crypto/elliptic"
	"sync"
)

var initonce sync.Once

// P256Sm2 returns the sm2 p256v1 curve.
func P256Sm2() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}
