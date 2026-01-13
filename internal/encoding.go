package asaburu

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

var charSetMap = make(map[string]encoding.Encoding, len(namedCharSetArr))

func init() {
	for _, v := range namedCharSetArr {
		charSetMap[v.name] = v.encoding
	}
}

func Charset() []string {
	var charSetArr = make([]string, len(namedCharSetArr))
	for i, ncs := range namedCharSetArr {
		charSetArr[i] = ncs.name
	}
	return charSetArr
}

func CharsetEncode(input string, chatset string) ([]byte, error) {
	if chatset == "UTF-8" {
		return []byte(input), nil
	}

	enc, ok := charSetMap[chatset]
	if !ok {
		return nil, errors.New("invalid chatset: " + chatset)
	}
	var buf bytes.Buffer
	writer := transform.NewWriter(&buf, enc.NewEncoder())
	defer writer.Close()

	_, err := io.WriteString(writer, input)
	if err != nil {
		LogError("failed to io.WriteString(writer, input)", err)
		return nil, err
	}
	return buf.Bytes(), nil
}

func CharsetDecode(input []byte, charset string) (string, error) {
	if charset == "UTF-8" {
		return string(input), nil
	}
	enc, ok := charSetMap[charset]
	if !ok {
		return "", errors.New("invalid charset: " + charset)
	}

	reader := transform.NewReader(bytes.NewReader(input), enc.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

type namedCharSet struct {
	name     string
	encoding encoding.Encoding
}

var namedCharSetArr = []namedCharSet{
	// Unicode
	{"UTF-8", unicode.UTF8},
	{"UTF-16LE", unicode.UTF16(unicode.LittleEndian, unicode.UseBOM)},
	{"UTF-16BE", unicode.UTF16(unicode.BigEndian, unicode.UseBOM)},

	// Han
	{"GBK", simplifiedchinese.GBK},
	{"GB18030", simplifiedchinese.GB18030},
	{"HZ-GB2312", simplifiedchinese.HZGB2312},
	{"Big5", traditionalchinese.Big5},

	{"Shift JIS", japanese.ShiftJIS},
	{"ISO-2022-JP", japanese.ISO2022JP},
	{"EUC-JP", japanese.EUCJP},
	{"EUC-KR", korean.EUCKR},

	// Charmap
	{"ISO 8859-1", charmap.ISO8859_1},
	{"ISO 8859-2", charmap.ISO8859_2},
	{"ISO 8859-3", charmap.ISO8859_3},
	{"ISO 8859-4", charmap.ISO8859_4},
	{"ISO 8859-5", charmap.ISO8859_5},
	{"ISO 8859-6", charmap.ISO8859_6},
	{"ISO 8859-7", charmap.ISO8859_7},
	{"ISO 8859-8", charmap.ISO8859_8},
	{"ISO 8859-10", charmap.ISO8859_10},
	{"ISO 8859-13", charmap.ISO8859_13},
	{"ISO 8859-14", charmap.ISO8859_14},
	{"ISO 8859-15", charmap.ISO8859_15},
	{"ISO 8859-16", charmap.ISO8859_16},
	{"Windows 1250", charmap.Windows1250},
	{"Windows 1251", charmap.Windows1251},
	{"Windows 1252", charmap.Windows1252},
	{"Windows 1253", charmap.Windows1253},
	{"Windows 1254", charmap.Windows1254},
	{"Windows 1255", charmap.Windows1255},
	{"Windows 1256", charmap.Windows1256},
	{"Windows 1257", charmap.Windows1257},
	{"Windows 1258", charmap.Windows1258},
	{"Macintosh", charmap.Macintosh},
	{"Macintosh Cyrillic", charmap.MacintoshCyrillic},
}
