package wasm

import (
	asaburu "asaburu/internal"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
)

const (
	RSA_KEY_FMT_PKCS1 = "PKCS#1"
	RSA_KEY_FMT_PKCS8 = "PKCS#8"
	RSA_KEY_FMT_PKIX  = "PKIX"

	RSA_KEY_SIZE_1024 = 1024
	RSA_KEY_SIZE_2048 = 2048
	RSA_KEY_SIZE_3072 = 3072
	RSA_KEY_SIZE_4096 = 4096

	RSA_PADDING_PKCS1V15 = "PKCS#1 v1.5"
	RSA_PADDING_PSS      = "PSS"
	RSA_PADDING_OAEP     = "OAEP"
)

type keyEnFunc func(key any) ([]byte, error)
type keyDeFunc func(der []byte) (any, error)

type keyObj struct {
	name   string
	tag    string
	enFunc keyEnFunc
	deFunc keyDeFunc
}

type rsaKey struct {
	name     string
	pubFunc  keyObj
	privFunc keyObj
}

var rsaKeyMap = func() map[string]*rsaKey {
	m := make(map[string]*rsaKey)
	for i := range rsaKeyArr {
		m[rsaKeyArr[i].name] = &rsaKeyArr[i]
	}
	return m
}()

func getRsaKey(format string) *rsaKey {
	return rsaKeyMap[format]
}

var (
	pubPKIX = keyObj{
		RSA_KEY_FMT_PKIX, "PUBLIC KEY", x509.MarshalPKIXPublicKey, x509.ParsePKIXPublicKey,
	}
	privPkcs1 = keyObj{RSA_KEY_FMT_PKCS1, "RSA PRIVATE KEY",
		func(privKey any) ([]byte, error) {
			if key, ok := privKey.(*rsa.PrivateKey); ok {
				return x509.MarshalPKCS1PrivateKey(key), nil
			}
			return nil, errors.New("invalid *rsa.PublicKey")
		},
		func(der []byte) (any, error) { return x509.ParsePKCS1PrivateKey(der) },
	}

	rsaKeyArr = []rsaKey{
		{"PKCS#1#1", keyObj{RSA_KEY_FMT_PKCS1, "RSA PUBLIC KEY",
			func(pubKey any) ([]byte, error) {
				if key, ok := pubKey.(*rsa.PublicKey); !ok {
					panic("invalid *rsa.PublicKey")
				} else {
					return x509.MarshalPKCS1PublicKey(key), nil
				}
			},
			func(der []byte) (any, error) { return x509.ParsePKCS1PublicKey(der) },
		}, privPkcs1},
		{RSA_KEY_FMT_PKCS1, pubPKIX, privPkcs1},
		{RSA_KEY_FMT_PKCS8, pubPKIX, keyObj{
			RSA_KEY_FMT_PKCS8, "PRIVATE KEY", x509.MarshalPKCS8PrivateKey, x509.ParsePKCS8PrivateKey,
		}},
	}
)

type RSA struct{}

type rsaParam struct {
	KeySize int    `json:"key_size"`
	KeyFmt  string `json:"key_fmt"`
	PrivKey string `json:"privkey"`
	Pubkey  string `json:"pubkey"`
	Padding string `json:"padding"`
	Hash    string `json:"hash"`
	Input   string `json:"input"`
	Charset string `json:"charset"`
}

func (RSA) parseParam(jsonStr string) (*rsaParam, error) {
	param := &rsaParam{}
	if err := json.Unmarshal([]byte(jsonStr), param); err != nil {
		asaburu.LogError("RSA parseParam, failed to json.Unmarshal", err)
		return nil, err
	}
	return param, nil
}

func (RSA) Variants() map[string]any {
	var arr []string
	for _, v := range rsaKeyArr {
		arr = append(arr, v.name)
	}

	return map[string]any{
		"key": map[string]any{
			"fmts":    arr,
			"sizes":   []int{RSA_KEY_SIZE_1024, RSA_KEY_SIZE_2048, RSA_KEY_SIZE_3072, RSA_KEY_SIZE_4096},
			"deffmt":  RSA_KEY_FMT_PKCS8,
			"defsize": RSA_KEY_SIZE_2048,
		},
		"hash": map[string]any{
			"def":      HASH_SHA_256.String(),
			"variants": Hash{}.Variants(),
			"modes":    []string{RSA_PADDING_PSS, RSA_PADDING_OAEP},
		},
		"modes": map[string]any{
			"crypto":    []string{RSA_PADDING_OAEP, RSA_PADDING_PKCS1V15},
			"signature": []string{RSA_PADDING_PSS, RSA_PADDING_PKCS1V15},
		},
	}
}

func (RSA) GenerateKey(bits int, format string) (map[string]map[string][]byte, error) {
	key := getRsaKey(format)
	if key == nil {
		return nil, errors.New("invalid key format: " + format)
	}
	asaburu.LogInfo("RSA GenerateKey", asaburu.LoSt{"pubkey.name": key.pubFunc.name, "privkey.name": key.privFunc.name})

	var priDer, pubDer []byte
	f := func() (string, error) {
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return "rsa.GenerateKey", err
		}
		priDer, err = key.privFunc.enFunc(privateKey)
		if err != nil {
			return "key.privFunc.enFunc", err
		}
		pubDer, err = key.pubFunc.enFunc(&privateKey.PublicKey)
		if err != nil {
			return "key.pubFunc.enFunc", err
		}
		return "", nil
	}
	if msg, err := f(); err != nil {
		asaburu.LogError("RSA GenerateKey, failed to "+msg, err)
		return nil, errors.New("failed to generate RSA key pairs")
	}

	return map[string]map[string][]byte{
		"der": {"privkey": priDer, "pubkey": pubDer},
		"pem": {
			"privkey": pem.EncodeToMemory(&pem.Block{Type: key.privFunc.tag, Bytes: priDer}),
			"pubkey":  pem.EncodeToMemory(&pem.Block{Type: key.pubFunc.tag, Bytes: pubDer}),
		},
	}, nil
}

func (r RSA) Encrypt(jsonStr string) (map[string]string, error) {
	asaburu.LogInfo("RSA Encrypt", asaburu.LoSt{"jsonStr": jsonStr})
	param, err := r.parseParam(jsonStr)
	if err != nil {
		return nil, errors.New("invalid param")
	}
	msg, err := asaburu.CharsetEncode(param.Input, param.Charset)
	if err != nil {
		asaburu.LogError("RSA Encrypt, failed to asaburu.CharsetEncode", err)
		return nil, errors.New("invalid charset: " + param.Charset)
	}

	data, err := r.makeKeyData(param.KeyFmt, param.Hash, param.Pubkey, "")
	if err != nil {
		asaburu.LogError("RSA Encrypt, failed to makeKeyData", err)
		return nil, err
	}

	cipherText, err := func(padding string, pubkey *rsa.PublicKey, msg []byte) ([]byte, error) {
		random := rand.Reader
		switch padding {
		case RSA_PADDING_PKCS1V15:
			return rsa.EncryptPKCS1v15(random, pubkey, msg)
		case RSA_PADDING_OAEP:
			return rsa.EncryptOAEP(data.hashObj.hmacFunc(), random, pubkey, msg, nil)
		default:
			return nil, errors.New("invalid padding: " + padding)
		}
	}(param.Padding, data.rsaPubkey, msg)
	if err != nil {
		asaburu.LogError("RSA Encrypt, failed to encrypt", err)
		return nil, errors.New("failed to aes encrypt")
	}
	return map[string]string{
		asaburu.ENC_HEX:    asaburu.EncodeToString(cipherText, asaburu.ENC_HEX),
		asaburu.ENC_BASE64: asaburu.EncodeToString(cipherText, asaburu.ENC_BASE64),
	}, nil
}

func (r RSA) Decrypt(jsonStr, enc string) (string, error) {
	asaburu.LogInfo("RSA Decrypt", asaburu.LoSt{"jsonStr": jsonStr, "enc": enc})
	param, err := r.parseParam(jsonStr)
	if err != nil {
		return "", errors.New("invalid param")
	}
	cipherText, err := asaburu.DecodeString(param.Input, enc)
	if err != nil {
		asaburu.LogError("RSA Decrypt, failed to asaburu.DecodeString", err)
		return "", errors.New("invalid input")
	}

	data, err := r.makeKeyData(param.KeyFmt, param.Hash, "", param.PrivKey)
	if err != nil {
		asaburu.LogError("RSA Decrypt, failed to makeKeyData", err)
		return "", err
	}

	plaintext, err := func(padding string, privkey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
		random := rand.Reader
		switch padding {
		case RSA_PADDING_PKCS1V15:
			return rsa.DecryptPKCS1v15(random, privkey, cipherText)
		case RSA_PADDING_OAEP:
			return rsa.DecryptOAEP(data.hashObj.hmacFunc(), random, privkey, cipherText, nil)
		default:
			return nil, errors.New("invalid padding: " + padding)
		}
	}(param.Padding, data.rsaPrivkey, cipherText)
	if err != nil {
		asaburu.LogError("RSA Decrypt, failed to decrypt", err)
		return "", errors.New("failed to aes decrypt")
	}

	if str, err := asaburu.CharsetDecode(plaintext, param.Charset); err != nil {
		asaburu.LogError("RSA Decrypt, failed to asaburu.CharsetDecode", err)
		return "", errors.New("invalid charset: " + param.Charset)
	} else {
		return str, nil
	}
}

func (r RSA) Sign(jsonStr string) (map[string]string, error) {
	asaburu.LogInfo("RSA Sign", asaburu.LoSt{"jsonStr": jsonStr})
	param, err := r.parseParam(jsonStr)
	if err != nil {
		return nil, errors.New("invalid param")
	}
	msg, err := asaburu.CharsetEncode(param.Input, param.Charset)
	if err != nil {
		asaburu.LogError("RSA Sign, failed to asaburu.CharsetEncode", err)
		return nil, errors.New("invalid charset: " + param.Charset)
	}
	data, err := r.makeKeyData(param.KeyFmt, param.Hash, "", param.PrivKey)
	if err != nil {
		asaburu.LogError("RSA Sign, failed to makeKeyData", err)
		return nil, err
	}

	digest := data.hashObj.digestFunc(msg)
	signature, err := func(padding string, privkey *rsa.PrivateKey, variant crypto.Hash, digest []byte) ([]byte, error) {
		random := rand.Reader
		switch padding {
		case RSA_PADDING_PKCS1V15:
			return rsa.SignPKCS1v15(random, privkey, variant, digest)
		case RSA_PADDING_PSS:
			return rsa.SignPSS(random, privkey, variant, digest, nil)
		default:
			return nil, errors.New("invalid padding: " + padding)
		}
	}(param.Padding, data.rsaPrivkey, data.hashObj.variant, digest)
	if err != nil {
		asaburu.LogError("RSA Sign, failed to sign", err)
		return nil, errors.New("failed to  aes sign")
	}
	return map[string]string{
		asaburu.ENC_HEX:    asaburu.EncodeToString(signature, asaburu.ENC_HEX),
		asaburu.ENC_BASE64: asaburu.EncodeToString(signature, asaburu.ENC_BASE64),
	}, nil
}

func (r RSA) Verify(jsonStr, enc, signature string) (bool, error) {
	asaburu.LogInfo("RSA Verify", asaburu.LoSt{"jsonStr": jsonStr, "enc": enc})
	param, err := r.parseParam(jsonStr)
	if err != nil {
		return false, errors.New("invalid param")
	}
	msg, err := asaburu.CharsetEncode(param.Input, param.Charset)
	if err != nil {
		asaburu.LogError("RSA Verify, failed to asaburu.CharsetEncode", err)
		return false, errors.New("invalid charset: " + param.Charset)
	}

	data, err := r.makeKeyData(param.KeyFmt, param.Hash, param.Pubkey, "")
	if err != nil {
		asaburu.LogError("RSA Verify, failed to makeKeyData", err)
		return false, err
	}

	signByte, err := asaburu.DecodeString(signature, enc)
	if err != nil {
		asaburu.LogError("RSA Verify, failed to asaburu.DecodeString", err)
		return false, errors.New("invalid signature")
	}

	digest := data.hashObj.digestFunc(msg)
	if err := func(padding string, pubkey *rsa.PublicKey, variant crypto.Hash, digest []byte, signByte []byte) error {
		switch padding {
		case RSA_PADDING_PKCS1V15:
			return rsa.VerifyPKCS1v15(data.rsaPubkey, data.hashObj.variant, digest, signByte)
		case RSA_PADDING_PSS:
			return rsa.VerifyPSS(data.rsaPubkey, data.hashObj.variant, digest, signByte, nil)
		default:
			return errors.New("invalid padding: " + padding)
		}
	}(param.Padding, data.rsaPubkey, data.hashObj.variant, digest, signByte); err != nil {
		asaburu.LogError("RSA Verify, failed to verify", err)
		return false, errors.New("failed to aes verify")
	}
	return true, nil
}

type rsaKeyData struct {
	rsaPubkey  *rsa.PublicKey
	rsaPrivkey *rsa.PrivateKey
	hashObj    *hashObj
}

func parsePemKey[T *rsa.PublicKey | *rsa.PrivateKey](pemStr string, deFunc func([]byte) (any, error)) (T, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	key, err := deFunc(block.Bytes)
	if err != nil {
		asaburu.LogError("RSA parsePemKey, failed to decode PEM key", err)
		return nil, err
	}
	if tKey, ok := key.(T); !ok {
		return nil, errors.New("invalid key type")
	} else {
		return tKey, nil
	}
}

func (RSA) makeKeyData(keyFmt, hash, pubKey, privKey string) (m *rsaKeyData, err error) {
	m = &rsaKeyData{}

	keyObj := getRsaKey(keyFmt)
	if keyObj == nil {
		return nil, errors.New("invalid key format: " + keyFmt)
	}
	if hash != "" {
		hashObj := Hash{}.GetHashObj(hash)
		if hashObj == nil {
			return nil, errors.New("invalid hash func: " + hash)
		}
		m.hashObj = hashObj
	}

	if pubKey != "" {
		pub, err := parsePemKey[*rsa.PublicKey](pubKey, keyObj.pubFunc.deFunc)
		if err != nil {
			asaburu.LogError("RSA makeKeyData, failed to parsePemKey", err)
			return nil, errors.New("invalid public key")
		}
		m.rsaPubkey = pub
	}

	if privKey != "" {
		priv, err := parsePemKey[*rsa.PrivateKey](privKey, keyObj.privFunc.deFunc)
		if err != nil {
			asaburu.LogError("RSA makeKeyData, failed to parsePemKey", err)
			return nil, errors.New("invalid private key")
		}
		m.rsaPrivkey = priv
	}
	return
}
