package wasm

import (
	asaburu "asaburu/internal"
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

const (
	HASH_MD5         = crypto.MD5
	HASH_SHA_1       = crypto.SHA1
	HASH_SHA_224     = crypto.SHA224
	HASH_SHA_256     = crypto.SHA256
	HASH_SHA_384     = crypto.SHA384
	HASH_SHA_512     = crypto.SHA512
	HASH_SHA512_224  = crypto.SHA512_224
	HASH_SHA512_256  = crypto.SHA512_256
	HASH_SHA3_224    = crypto.SHA3_224
	HASH_SHA3_256    = crypto.SHA3_256
	HASH_SHA3_384    = crypto.SHA3_384
	HASH_SHA3_512    = crypto.SHA3_512
	HASH_BLAKE2S_256 = crypto.BLAKE2s_256
	HASH_BLAKE2B_256 = crypto.BLAKE2b_256
	HASH_BLAKE2B_384 = crypto.BLAKE2b_384
	HASH_BLAKE2B_512 = crypto.BLAKE2b_512
)

type hashObj struct {
	variant    crypto.Hash
	digestFunc func([]byte) []byte
	hmacFunc   func() hash.Hash
}

var hashArr = []hashObj{
	{HASH_MD5, func(b []byte) []byte { sum := md5.Sum(b); return sum[:] }, md5.New},
	{HASH_SHA_1, func(b []byte) []byte { h := sha1.Sum(b); return h[:] }, sha1.New},
	{HASH_SHA_224, func(b []byte) []byte { h := sha256.Sum224(b); return h[:] }, sha256.New224},
	{HASH_SHA_256, func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }, sha256.New},
	{HASH_SHA_384, func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }, sha512.New384},
	{HASH_SHA_512, func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }, sha512.New},
	{HASH_SHA512_224, func(b []byte) []byte { h := sha512.Sum512_224(b); return h[:] }, sha512.New512_224},
	{HASH_SHA512_256, func(b []byte) []byte { h := sha512.Sum512_256(b); return h[:] }, sha512.New512_256},
	{HASH_SHA3_224, func(b []byte) []byte { h := sha3.Sum224(b); return h[:] }, func() hash.Hash { return sha3.New224() }},
	{HASH_SHA3_256, func(b []byte) []byte { h := sha3.Sum256(b); return h[:] }, func() hash.Hash { return sha3.New256() }},
	{HASH_SHA3_384, func(b []byte) []byte { h := sha3.Sum384(b); return h[:] }, func() hash.Hash { return sha3.New384() }},
	{HASH_SHA3_512, func(b []byte) []byte { h := sha3.Sum512(b); return h[:] }, func() hash.Hash { return sha3.New512() }},
	{HASH_BLAKE2S_256, func(b []byte) []byte { h := blake2s.Sum256(b); return h[:] }, func() hash.Hash { h, _ := blake2s.New256(nil); return h }},
	{HASH_BLAKE2B_256, func(b []byte) []byte { h := blake2b.Sum256(b); return h[:] }, func() hash.Hash { h, _ := blake2b.New256(nil); return h }},
	{HASH_BLAKE2B_384, func(b []byte) []byte { h := blake2b.Sum384(b); return h[:] }, func() hash.Hash { h, _ := blake2b.New384(nil); return h }},
	{HASH_BLAKE2B_512, func(b []byte) []byte { h := blake2b.Sum512(b); return h[:] }, func() hash.Hash { h, _ := blake2b.New512(nil); return h }},
}

var hashMap = func() map[string]*hashObj {
	m := make(map[string]*hashObj)
	for i := range hashArr {
		m[hashArr[i].variant.String()] = &hashArr[i]
	}
	return m
}()

type Hash struct{}

func (Hash) GetHashObj(name string) *hashObj {
	return hashMap[name]
}

func (Hash) Variants() []string {
	var arr []string
	for _, v := range hashArr {
		arr = append(arr, v.variant.String())
	}
	return arr
}

func (Hash) Digest(args []string) (map[string]string, error) {
	input, charset, enc := args[0], args[1], args[2]
	asaburu.LogInfo("Hash Digest", asaburu.LoSt{"input": input, "charset": charset, "enc": enc})

	if !asaburu.IsValidEncode(enc) {
		return nil, errors.New("invalid enc: " + enc)
	}

	byteArr, err := asaburu.CharsetEncode(input, charset)
	if err != nil {
		asaburu.LogError("Hash Digest, failed to asaburu.CharsetEncode", err)
		return nil, errors.New("invalid charset: " + charset)
	}

	sumMap := make(map[string]string)
	for _, v := range hashArr {
		b := v.digestFunc(byteArr)
		sumMap[v.variant.String()] = asaburu.EncodeToString(b, enc)
	}
	return sumMap, nil
}

func (Hash) Hmac(args []string) (map[string]string, error) {
	input, charset, key, keyenc, enc := args[0], args[1], args[2], args[3], args[4]
	asaburu.LogInfo("Hash Hmac", asaburu.LoSt{"input": input, "charset": charset, "key": key, "keyenc": keyenc, "enc": enc})

	if !asaburu.IsValidEncode(enc) {
		return nil, errors.New("invalid enc: " + enc)
	}

	byteArr, err := asaburu.CharsetEncode(input, charset)
	if err != nil {
		asaburu.LogError("Hash Hmac, failed to asaburu.CharsetEncode", err)
		return nil, errors.New("invalid charset: " + charset)
	}

	keyBytes, err := asaburu.DecodeString(key, keyenc)
	if err != nil {
		asaburu.LogError("Hash Hmac, failed to asaburu.DecodeString", err)
		return nil, errors.New("invalid key, key: " + key + ", keyenc: " + keyenc)
	}
	sumMap := make(map[string]string)
	for _, v := range hashArr {
		mac := hmac.New(v.hmacFunc, keyBytes)
		if _, err := mac.Write(byteArr); err != nil {
			asaburu.LogError("Hash Hmac, failed to mac.Write, variant"+v.variant.String(), err)
			return nil, errors.New("failed to do hmac " + v.variant.String() + " encode")
		} else {
			sumMap[v.variant.String()] = asaburu.EncodeToString(mac.Sum(nil), enc)
		}
	}
	return sumMap, nil
}
