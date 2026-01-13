package main

import (
	wasm "asaburu/go"
	asaburu "asaburu/internal"
	"errors"
	"strconv"
	"syscall/js"

	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"
)

func main() {
	js.Global().Set("charset", f(asaburu.Charset))

	js.Global().Set("full", ff(1, func(args []string) (any, error) {
		return norm.NFC.String(width.Widen.String(args[0])), nil
	}))
	js.Global().Set("half", ff(1, func(args []string) (any, error) {
		return width.Narrow.String(norm.NFD.String(args[0])), nil
	}))

	radixWasm := wasm.Radix{}
	js.Global().Set("radixVariants", f(radixWasm.Variants))
	js.Global().Set("radixConv", ff(2, radixWasm.Conv))

	baseWasm := wasm.Base{}
	js.Global().Set("baseVariants", f(baseWasm.Variants))
	js.Global().Set("baseEncode", ff(3, baseWasm.Encode))
	js.Global().Set("baseDecode", ff(3, baseWasm.Decode))

	hashWasm := wasm.Hash{}
	js.Global().Set("hashVariants", f(hashWasm.Variants))
	js.Global().Set("digest", ff(3, hashWasm.Digest))
	js.Global().Set("hmac", ff(5, hashWasm.Hmac))

	aesWasm := wasm.AES{}
	js.Global().Set("aesVariants", f(aesWasm.Variants))
	js.Global().Set("aesEncrypt", ff(1, func(args []string) (any, error) { return aesWasm.Encrypt(args[0]) }))
	js.Global().Set("aesDecrypt", ff(2, func(args []string) (any, error) { return aesWasm.Decrypt(args[0], args[1]) }))

	rsaWasm := wasm.RSA{}
	js.Global().Set("rsaVariants", f(rsaWasm.Variants))
	js.Global().Set("rsaGenerateKey", ff(2, func(args []string) (any, error) {
		bits, err := strconv.Atoi(args[0])
		if err != nil {
			asaburu.LogError("rsaGenerateKey, Error: invalid key size: "+args[0], nil)
			return nil, errors.New("invalid key size")
		}
		asaburu.LogInfo("rsaGenerateKey", asaburu.LoSt{"bits": args[0], "format": args[1]})
		return rsaWasm.GenerateKey(bits, args[1])
	}))
	js.Global().Set("rsaEncrypt", ff(1, func(args []string) (any, error) { return rsaWasm.Encrypt(args[0]) }))
	js.Global().Set("rsaDecrypt", ff(2, func(args []string) (any, error) { return rsaWasm.Decrypt(args[0], args[1]) }))
	js.Global().Set("rsaSign", ff(1, func(args []string) (any, error) { return rsaWasm.Sign(args[0]) }))
	js.Global().Set("rsaVerify", ff(3, func(args []string) (any, error) { return rsaWasm.Verify(args[0], args[1], args[2]) }))

	asaburu.LogInfo("Hello from TinyGo WASM!", nil)
	select {}
}

func f[T any](f func() T) js.Func {
	return js.FuncOf(func(_ js.Value, _ []js.Value) any {
		data := f()
		return asaburu.Result{Data: data}.ToJSON()
	})
}

func ff[T any](n int, f func([]string) (T, error)) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != n {
			err := errors.New(strconv.Itoa(n) + " arguments required but got " + strconv.Itoa(len(args)))
			return js.ValueOf(asaburu.Result{Error: err.Error()}.ToJSON())
		}
		argsArr := make([]string, n)
		for i, arg := range args {
			argsArr[i] = arg.String()
		}
		var errstr = ""
		re, err := f(argsArr)
		if err != nil {
			errstr = err.Error()
		}
		return js.ValueOf(asaburu.Result{Data: re, Error: errstr}.ToJSON())
	})
}

func secureRandom(n int) ([]byte, error) {
	array := js.Global().Get("Uint8Array").New(n)
	js.Global().Get("crypto").Call("getRandomValues", array)
	dst := make([]byte, n)
	js.CopyBytesToGo(dst, array)
	return dst, nil
}
