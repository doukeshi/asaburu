package wasm

import (
	asaburu "asaburu/internal"
	"errors"
	"math/big"
	"strconv"
)

type Radix struct{}

type radixObj struct {
	base  int
	name  string
	regex string
}

var radixArr = []radixObj{
	{2, "binary", "^[01]+$"},
	{8, "octal", "^[0-7]+$"},
	{10, "decimal", "^[0-9]+$"},
	{16, "hex", "^[0-9A-Fa-f]+$"},
	{32, "base32", "^[0-9A-Va-v]+$"},
	{36, "base36", "^[0-9A-Za-z]+$"},
}

func (Radix) Variants() []map[string]any {
	var arr []map[string]any
	for _, v := range radixArr {
		arr = append(arr, map[string]any{
			"base":  v.base,
			"name":  v.name,
			"regex": v.regex,
		})
	}
	return arr
}

func (Radix) Conv(args []string) (map[string]string, error) {
	radixStr, number := args[0], args[1]
	asaburu.LogInfo("Radix Conv", asaburu.LoSt{"radix": radixStr, "number": number})

	isValidRadix := func(r int) bool {
		for _, obj := range radixArr {
			if r == obj.base {
				return true
			}
		}
		return false
	}
	radix, err := strconv.Atoi(radixStr)
	if err != nil || !isValidRadix(radix) {
		return nil, errors.New("invalid radix: " + radixStr)
	}

	if decimal, err := strconv.ParseInt(number, radix, 64); err == nil {
		return map[string]string{
			"binary":  strconv.FormatInt(decimal, 2),
			"octal":   strconv.FormatInt(decimal, 8),
			"decimal": strconv.FormatInt(decimal, 10),
			"hex":     strconv.FormatInt(decimal, 16),
			"base32":  strconv.FormatInt(decimal, 32),
			"base36":  strconv.FormatInt(decimal, 36),
		}, nil
	} else if !errors.Is(err, strconv.ErrRange) {
		asaburu.LogError("Radix Conv, failed to strconv.ParseInt", err)
		return nil, errors.New("invalid number: " + number)
	}

	asaburu.LogInfo("Radix Conv, using big.Int fallback", nil)
	bigInt := new(big.Int)
	if _, ok := bigInt.SetString(number, radix); !ok {
		asaburu.LogError("Radix Conv, failed to bigInt.SetString", nil)
		return nil, errors.New("invalid radix: " + radixStr + ", number: " + number)
	}
	return map[string]string{
		"binary":  bigInt.Text(2),
		"octal":   bigInt.Text(8),
		"decimal": bigInt.Text(10),
		"hex":     bigInt.Text(16),
		"base32":  bigInt.Text(32),
		"base36":  bigInt.Text(36),
	}, nil
}
