package wasm

import (
	asaburu "asaburu/internal"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
)

const (
	AES_BLOCK_SIZE = aes.BlockSize

	AES_MODE_ECB  = "ECB"
	AES_MODE_CBC  = "CBC"
	AES_MODE_PCBC = "PCBC"
	AES_MODE_CFB  = "CFB"
	AES_MODE_OFB  = "OFB"
	AES_MODE_CTR  = "CTR"

	AES_PADDING_PKCS7    = "PKCS#7"     // padding bytes equal to the padding size
	AES_PADDING_Zero     = "Zero"       // 0x00 padding
	AES_PADDING_ANSIX923 = "ANSI X9.23" // 0x00 padding, with the last byte being the padding size
	AES_PADDING_ISO7816  = "ISO 7816"   // 0x80 followed by 0x00 padding
	AES_PADDING_ISO10126 = "ISO 10126"  // random padding and the last byte as the size
)

var aesStreamModes = map[string]struct{}{AES_MODE_CFB: {}, AES_MODE_OFB: {}, AES_MODE_CTR: {}}

func aesUnpadding(data []byte) ([]byte, error) {
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > len(data) {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padLen], nil
}

type padFunc func(data []byte, padding int) []byte
type unpadFunc func(data []byte) ([]byte, error)
type aesPadObj struct {
	name      string
	padFunc   padFunc
	unpadFunc unpadFunc
}

var padArr = []aesPadObj{
	{AES_PADDING_PKCS7,
		func(data []byte, padding int) []byte {
			return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
		}, aesUnpadding},

	{AES_PADDING_Zero,
		func(data []byte, padding int) []byte {
			return append(data, make([]byte, padding)...)
		}, func(data []byte) ([]byte, error) {
			return data, nil
		}},

	{AES_PADDING_ANSIX923,
		func(data []byte, padding int) []byte {
			return append(data, append(make([]byte, padding-1), byte(padding))...)
		}, aesUnpadding},

	{AES_PADDING_ISO7816,
		func(data []byte, padding int) []byte {
			return append(data, append([]byte{0x80}, make([]byte, padding-1)...)...)
		}, func(data []byte) ([]byte, error) {
			// remove trailing 0x00 bytes, then remove the 0x80 byte
			i := len(data)
			for i > 0 && data[i-1] == 0 {
				i--
			}
			if i > 0 && data[i-1] == 0x80 {
				i--
			}
			return data[:i], nil
		}},

	{AES_PADDING_ISO10126, func(data []byte, padding int) []byte {
		randBytes := make([]byte, padding-1)
		if _, err := rand.Read(randBytes); err != nil {
			asaburu.LogError("AES, failed to rand.Read", err)
			panic(err)
		}
		return append(data, append(randBytes, byte(padding))...)
	}, aesUnpadding},
}

type aesObj struct {
	name        string
	iv          bool
	pad         bool
	encryptFunc func(block cipher.Block, input, iv []byte, pf padFunc) []byte
	decryptFunc func(block cipher.Block, input, iv []byte, uf unpadFunc) ([]byte, error)
}

var aesArr = []aesObj{
	{AES_MODE_ECB, false, true,
		func(b cipher.Block, in, iv []byte, pf padFunc) []byte {
			return aesBlockEncrypt(AES_MODE_ECB, b, in, iv, pf)
		}, func(b cipher.Block, in, iv []byte, uf unpadFunc) ([]byte, error) {
			return aesBlockDecrypt(AES_MODE_ECB, b, in, iv, uf)
		},
	}, {AES_MODE_CBC, true, true,
		func(b cipher.Block, in, iv []byte, pf padFunc) []byte {
			return aesBlockEncrypt(AES_MODE_CBC, b, in, iv, pf)
		}, func(b cipher.Block, in, iv []byte, uf unpadFunc) ([]byte, error) {
			return aesBlockDecrypt(AES_MODE_CBC, b, in, iv, uf)
		},
	}, {AES_MODE_PCBC, true, true,
		func(b cipher.Block, in, iv []byte, pf padFunc) []byte {
			return aesBlockEncrypt(AES_MODE_PCBC, b, in, iv, pf)
		}, func(b cipher.Block, in, iv []byte, uf unpadFunc) ([]byte, error) {
			return aesBlockDecrypt(AES_MODE_PCBC, b, in, iv, uf)
		},
	}, {AES_MODE_CFB, true, false,
		func(b cipher.Block, in, iv []byte, _ padFunc) []byte {
			return aesCFBCrypt(b, in, iv, false)
		}, func(b cipher.Block, in, iv []byte, _ unpadFunc) ([]byte, error) {
			return aesCFBCrypt(b, in, iv, true), nil
		},
	}, {AES_MODE_OFB, true, false,
		func(b cipher.Block, in, iv []byte, _ padFunc) []byte {
			return aesStreamCrypt(AES_MODE_OFB, b, in, iv)
		}, func(b cipher.Block, in, iv []byte, _ unpadFunc) ([]byte, error) {
			return aesStreamCrypt(AES_MODE_OFB, b, in, iv), nil
		},
	}, {AES_MODE_CTR, true, false,
		func(b cipher.Block, in, iv []byte, _ padFunc) []byte {
			return aesStreamCrypt(AES_MODE_CTR, b, in, iv)
		}, func(b cipher.Block, in, iv []byte, _ unpadFunc) ([]byte, error) {
			return aesStreamCrypt(AES_MODE_CTR, b, in, iv), nil
		},
	},
}

type AES struct{}

type aesParam struct {
	Mode    string `json:"mode"`
	Input   string `json:"input"`
	Charset string `json:"charset"`
	Key     string `json:"key"`
	KeyEnc  string `json:"key_enc"`
	IV      string `json:"iv"`
	IVEnc   string `json:"iv_enc"`
	Pad     string `json:"pad"`
}

func (AES) Variants() map[string]any {
	var modes []map[string]any
	for _, v := range aesArr {
		modes = append(modes, map[string]any{"name": v.name, "iv": v.iv, "pad": v.pad})
	}
	var pads []string
	for _, v := range padArr {
		pads = append(pads, v.name)
	}

	return map[string]any{
		"modes":    modes,
		"paddings": pads,
		"defmode":  AES_MODE_CBC,
		"defpad":   AES_PADDING_PKCS7,
	}
}

func (AES) Encrypt(jsonStr string) (map[string]string, error) {
	asaburu.LogInfo("AES Encrypt", asaburu.LoSt{"jsonStr": jsonStr})

	ab, err := NewAESByte(jsonStr)
	if err != nil {
		return nil, err
	}
	param := ab.param

	msg, err := asaburu.CharsetEncode(param.Input, param.Charset)
	if err != nil {
		asaburu.LogError("AES Encrypt, failed to asaburu.CharsetEncode", err)
		return nil, errors.New("invalid charset: " + param.Charset)
	}

	cipherText := ab.variant.encryptFunc(ab.block, msg, ab.ivByteArr, ab.padFunc)
	return map[string]string{
		asaburu.ENC_HEX:    asaburu.EncodeToString(cipherText, asaburu.ENC_HEX),
		asaburu.ENC_BASE64: asaburu.EncodeToString(cipherText, asaburu.ENC_BASE64),
	}, nil
}

func (AES) Decrypt(jsonStr, enc string) (string, error) {
	asaburu.LogInfo("AES Decrypt", asaburu.LoSt{"jsonStr": jsonStr, "enc": enc})

	ab, err := NewAESByte(jsonStr)
	if err != nil {
		return "", err
	}
	param := ab.param

	cipherText, err := asaburu.DecodeString(param.Input, enc)
	if err != nil {
		asaburu.LogError("AES Decrypt, failed to asaburu.DecodeString", err)
		return "", errors.New("invalid input, input: " + param.Input + ", enc: " + enc)
	}

	checkCipherTextSize := func(mode string, cipherText []byte) bool {
		_, ok := aesStreamModes[mode]
		return ok || len(cipherText)%AES_BLOCK_SIZE == 0
	}
	if !checkCipherTextSize(param.Mode, cipherText) {
		return "", errors.New("invalid input data")
	}

	plaintext, err := ab.variant.decryptFunc(ab.block, cipherText, ab.ivByteArr, ab.unpadFunc)
	if err != nil {
		asaburu.LogError("AES Decrypt, failed to ab.variant.decryptFunc", err)
		return "", errors.New("failed to do aes decrypt")
	}

	if str, err := asaburu.CharsetDecode(plaintext, param.Charset); err != nil {
		asaburu.LogError("AES Decrypt, failed to asaburu.CharsetDecode", err)
		return "", errors.New("failed to decode with charset: " + param.Charset)
	} else {
		return str, nil
	}
}

type aesMode struct {
	param                 *aesParam
	variant               *aesObj
	keyByteArr, ivByteArr []byte
	padFunc               padFunc
	unpadFunc             unpadFunc
	block                 cipher.Block
}

func NewAESByte(jsonStr string) (am *aesMode, err error) {
	am = &aesMode{}

	param := aesParam{}
	if err := json.Unmarshal([]byte(jsonStr), &param); err != nil {
		asaburu.LogError("AES Encrypt, failed to json.Unmarshal", err)
		return nil, errors.New("invalid param")
	}
	am.param = &param

	var variant *aesObj
	for i := range aesArr {
		if aesArr[i].name == param.Mode {
			variant = &aesArr[i]
			break
		}
	}
	if variant == nil {
		return nil, errors.New("invalid aes mode")

	}
	am.variant = variant

	if am.variant.iv {
		if param.IV == "" || param.IVEnc == "" {
			return nil, errors.New("invalid iv")
		}
		ivByteArr, err := asaburu.DecodeString(param.IV, param.IVEnc)
		if err != nil {
			asaburu.LogError("AES NewAesByte, failed to asaburu.DecodeString iv", err)
			return nil, errors.New("invalid iv")

		}
		if len(ivByteArr) != AES_BLOCK_SIZE {
			return nil, errors.New("invalid iv size")
		}
		am.ivByteArr = ivByteArr
	}
	if am.variant.pad {
		var padMap = make(map[string]aesPadObj)
		for _, x := range padArr {
			padMap[x.name] = x
		}
		padObj, ok := padMap[param.Pad]
		if !ok {
			return nil, errors.New("invalid padType")
		}
		am.padFunc, am.unpadFunc = padObj.padFunc, padObj.unpadFunc
	}

	if keyByteArr, err := asaburu.DecodeString(param.Key, param.KeyEnc); err != nil {
		asaburu.LogError("AES NewAesByte, failed to asaburu.DecodeString key", err)
		return nil, errors.New("invalid key")

	} else {
		if size := len(keyByteArr); size != 16 && size != 24 && size != 32 {
			return nil, errors.New("invalid key size, AES key must be 16/24/32 bytes")
		}
		am.keyByteArr = keyByteArr
	}
	if block, err := aes.NewCipher(am.keyByteArr); err != nil {
		asaburu.LogError("AES NewAesByte, failed to aes.NewCipher", err)
		return nil, errors.New("invalid key")
	} else {
		am.block = block
	}
	return
}

// for ECB/CBC/PCBC
func aesBlockEncrypt(mode string, block cipher.Block, input, iv []byte, pf padFunc) []byte {
	padding := AES_BLOCK_SIZE - len(input)%AES_BLOCK_SIZE
	plain := pf(input, padding)

	out := make([]byte, len(plain))
	switch mode {
	case AES_MODE_ECB:
		for i := 0; i < len(plain); i += AES_BLOCK_SIZE {
			block.Encrypt(out[i:i+AES_BLOCK_SIZE], plain[i:i+AES_BLOCK_SIZE])
		}
	case AES_MODE_CBC:
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(out, plain)
	case AES_MODE_PCBC:
		prevCipher := iv
		prevPlain := make([]byte, AES_BLOCK_SIZE)
		tmp := make([]byte, AES_BLOCK_SIZE)

		for i := 0; i < len(plain); i += AES_BLOCK_SIZE {
			for j := 0; j < AES_BLOCK_SIZE; j++ {
				tmp[j] = plain[i+j] ^ prevCipher[j] ^ prevPlain[j]
			}
			block.Encrypt(out[i:i+AES_BLOCK_SIZE], tmp)
			copy(prevPlain, plain[i:i+AES_BLOCK_SIZE])
			copy(prevCipher, out[i:i+AES_BLOCK_SIZE])
		}
	}
	return out
}

func aesBlockDecrypt(mode string, block cipher.Block, input, iv []byte, uf unpadFunc) ([]byte, error) {
	plain := make([]byte, len(input))
	switch mode {
	case AES_MODE_ECB:
		for i := 0; i < len(input); i += AES_BLOCK_SIZE {
			block.Decrypt(plain[i:i+AES_BLOCK_SIZE], input[i:i+AES_BLOCK_SIZE])
		}
	case AES_MODE_CBC:
		cbc := cipher.NewCBCDecrypter(block, iv)
		cbc.CryptBlocks(plain, input)
	case AES_MODE_PCBC:
		prevCipher := iv
		prevPlain := make([]byte, AES_BLOCK_SIZE)
		for i := 0; i < len(input); i += AES_BLOCK_SIZE {
			block.Decrypt(plain[i:i+AES_BLOCK_SIZE], input[i:i+AES_BLOCK_SIZE])
			for j := 0; j < AES_BLOCK_SIZE; j++ {
				plain[i+j] ^= prevCipher[j] ^ prevPlain[j]
			}
			copy(prevPlain, plain[i:i+AES_BLOCK_SIZE])
			copy(prevCipher, input[i:i+AES_BLOCK_SIZE])
		}
	}
	return uf(plain)
}

// for OFB/CTR
func aesStreamCrypt(mode string, block cipher.Block, input, iv []byte) []byte {
	out := make([]byte, len(input))
	var cs cipher.Stream
	switch mode {
	case AES_MODE_OFB:
		cs = cipher.NewOFB(block, iv)
	case AES_MODE_CTR:
		cs = cipher.NewCTR(block, iv)
	}
	cs.XORKeyStream(out, input)
	return out
}

// for CFB
func aesCFBCrypt(block cipher.Block, input, iv []byte, decrypt bool) []byte {
	out := make([]byte, len(input))
	var cs cipher.Stream
	if decrypt {
		cs = cipher.NewCFBDecrypter(block, iv)
	} else {
		cs = cipher.NewCFBEncrypter(block, iv)
	}
	cs.XORKeyStream(out, input)
	return out
}
