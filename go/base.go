package wasm

import (
	asaburu "asaburu/internal"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

type baseObj struct {
	name     string
	alphabet string
	regex    string
	enfunc   func([]byte) string
	defunc   func(string) ([]byte, error)
}

var baseArr = []baseObj{
	{"base16", "0123456789abcdef", "^[0-9a-fA-F]+$", hex.EncodeToString, hex.DecodeString},
	{"base32", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "^[A-Z2-7]+=*$", base32.StdEncoding.EncodeToString, base32.StdEncoding.DecodeString},
	{"base32hex", "0123456789ABCDEFGHIJKLMNOPQRSTUV", "^[0-9A-V]+=*$", base32.HexEncoding.EncodeToString, base32.HexEncoding.DecodeString},
	{"base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "^[A-Za-z0-9+/]+={0,2}$", base64.StdEncoding.EncodeToString, base64.StdEncoding.DecodeString},
	{"base64url", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "^[A-Za-z0-9-_]+={0,2}$", base64.URLEncoding.EncodeToString, base64.URLEncoding.DecodeString},
	{"base85", "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu",
		"^[0-9A-Za-uz!\"#$%&'()*+,-./:;<=>?@\\[\\\\]^_]+$",
		func(src []byte) string {
			buf := make([]byte, ascii85.MaxEncodedLen(len(src)))
			n := ascii85.Encode(buf, src)
			return string(buf[:n])
		},
		func(s string) ([]byte, error) {
			buf := make([]byte, len(s))
			n, _, err := ascii85.Decode(buf, []byte(s), true)
			if err != nil {
				return nil, errors.New("failed to ascii85.Decode, Error: " + err.Error())
			}
			return buf[:n], nil
		},
	},
}

var baseMap = func() map[string]*baseObj {
	m := make(map[string]*baseObj)
	for i := range baseArr {
		m[baseArr[i].name] = &baseArr[i]
	}
	return m
}()

type Base struct{}

func (Base) getBaseObj(name string) *baseObj {
	return baseMap[name]
}

func (Base) Variants() []map[string]string {
	var arr []map[string]string
	for _, v := range baseArr {
		arr = append(arr, map[string]string{
			"name":     v.name,
			"alphabet": v.alphabet,
			"regex":    v.regex,
		})
	}
	return arr
}

func (b Base) Encode(args []string) (string, error) {
	variant, input, charset := args[0], args[1], args[2]
	asaburu.LogInfo("Base Encode", asaburu.LoSt{"variant": variant, "input": input, "charset": charset})

	byteArr, err := asaburu.CharsetEncode(input, charset)
	if err != nil {
		asaburu.LogError("Base Encode, failed to asaburu.CharsetEncode", err)
		return "", errors.New("invalid charset: " + charset)
	}

	x := b.getBaseObj(variant)
	if x == nil {
		return "", errors.New("invalid variant: " + variant)
	}
	return x.enfunc(byteArr), nil
}

func (b Base) Decode(args []string) (string, error) {
	variant, input, charset := args[0], args[1], args[2]
	asaburu.LogInfo("Base Decode", asaburu.LoSt{"variant": variant, "input": input, "charset": charset})

	x := b.getBaseObj(variant)
	if x == nil {
		return "", errors.New("invalid variant: " + variant)
	}

	byteArr, err := x.defunc(input)
	if err != nil {
		asaburu.LogError("Base Decode, failed to x.defunc", err)
		return "", errors.New("invalid variant: " + variant)
	}

	decoded, err := asaburu.CharsetDecode(byteArr, charset)
	if err != nil {
		asaburu.LogError("Base Decode, failed to asaburu.CharsetDecode", err)
		return "", errors.New("invalid charset: " + charset)
	}

	return decoded, nil
}
