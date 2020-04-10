## Crypto国密算法包

### SM2 使用

```
//生成key
pri, _ := GenerateKey(rand.Reader)
hasher := sm3.New()
//生成签名
r, s, err := Sign(rand.Reader, pri, "", msg, hasher)
if err != nil {
	t.Fatalf("signing error: %s", err)
}
//验证签名
if !Verify(&pri.PublicKey, "", msg, hasher, r, s) {
	t.Error("verification failed")
}

```

### SM3 使用

```
//生成key
h:=sm3.New()
h.Reset()
h.Write("hello world")
hashed:=h.Sum(nil)

```

### SM4 使用

```  
key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
plainText := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
cipher := []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46}
加密
block, _ := sm4.NewCipher(key)
out := make([]byte, len(plainText))
block.Encrypt(out, plainText)

// 解密
block, _ := sm4.NewCipher(key)
out := make([]byte, len(cipher))
block.Decrypt(out, cipher) 

```
