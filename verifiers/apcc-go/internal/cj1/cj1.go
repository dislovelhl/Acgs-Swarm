// Package cj1 implements the bounded APCC-CJ1 wire profile independently of
// the Python protocol implementation.
package cj1

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	MaxPayloadBytes  = 1024 * 1024
	MaxEnvelopeBytes = (MaxPayloadBytes * 4 / 3) + 2048
	MaxDepth         = 8
)

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

type Value any
type Object map[string]Value
type Array []Value
type forbiddenLiteral struct{}

type parser struct {
	raw []byte
	pos int
}

func Parse(raw []byte, maxBytes int) (Value, *Error) {
	if len(raw) > maxBytes {
		return nil, fail("SIZE_LIMIT_EXCEEDED")
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, fail("INVALID_UNICODE")
	}
	p := &parser{raw: raw}
	value, err := p.value(1)
	if err != nil {
		return nil, err
	}
	if p.pos != len(raw) {
		return nil, fail("TRAILING_BYTES")
	}
	canonical, err := Encode(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, raw) {
		return nil, fail("NONCANONICAL_ENCODING")
	}
	return value, nil
}

func fail(code string) *Error { return &Error{Code: code} }

func (p *parser) value(depth int) (Value, *Error) {
	if depth > MaxDepth {
		return nil, fail("DEPTH_LIMIT_EXCEEDED")
	}
	p.space()
	if p.pos >= len(p.raw) {
		return nil, fail("MALFORMED_JSON")
	}
	switch p.raw[p.pos] {
	case '{':
		return p.object(depth)
	case '[':
		return p.array(depth)
	case '"':
		return p.string()
	case 't':
		if !bytes.HasPrefix(p.raw[p.pos:], []byte("true")) {
			return nil, fail("MALFORMED_JSON")
		}
		p.pos += len("true")
		return forbiddenLiteral{}, nil
	case 'f':
		if !bytes.HasPrefix(p.raw[p.pos:], []byte("false")) {
			return nil, fail("MALFORMED_JSON")
		}
		p.pos += len("false")
		return forbiddenLiteral{}, nil
	case 'n':
		if !bytes.HasPrefix(p.raw[p.pos:], []byte("null")) {
			return nil, fail("MALFORMED_JSON")
		}
		p.pos += len("null")
		return forbiddenLiteral{}, nil
	case '-':
		if p.pos+1 >= len(p.raw) || p.raw[p.pos+1] < '0' || p.raw[p.pos+1] > '9' {
			return nil, fail("MALFORMED_JSON")
		}
		return nil, fail("WRONG_JSON_TYPE")
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return nil, fail("WRONG_JSON_TYPE")
	default:
		return nil, fail("MALFORMED_JSON")
	}
}

func (p *parser) object(depth int) (Value, *Error) {
	p.pos++
	obj := Object{}
	p.space()
	if p.take('}') {
		return obj, nil
	}
	for {
		p.space()
		if p.pos >= len(p.raw) || p.raw[p.pos] != '"' {
			return nil, fail("MALFORMED_JSON")
		}
		key, err := p.string()
		if err != nil {
			return nil, err
		}
		if !isASCII(key) {
			return nil, fail("UNKNOWN_FIELD")
		}
		if _, exists := obj[key]; exists {
			return nil, fail("DUPLICATE_FIELD")
		}
		p.space()
		if !p.take(':') {
			return nil, fail("MALFORMED_JSON")
		}
		value, valueErr := p.value(depth + 1)
		if valueErr != nil {
			return nil, valueErr
		}
		obj[key] = value
		p.space()
		if p.take('}') {
			return obj, nil
		}
		if !p.take(',') {
			return nil, fail("MALFORMED_JSON")
		}
	}
}

func (p *parser) array(depth int) (Value, *Error) {
	p.pos++
	items := Array{}
	p.space()
	if p.take(']') {
		return items, nil
	}
	for {
		value, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		items = append(items, value)
		p.space()
		if p.take(']') {
			return items, nil
		}
		if !p.take(',') {
			return nil, fail("MALFORMED_JSON")
		}
	}
}

func (p *parser) string() (string, *Error) {
	if !p.take('"') {
		return "", fail("MALFORMED_JSON")
	}
	var out []rune
	segment := p.pos
	for p.pos < len(p.raw) {
		char := p.raw[p.pos]
		if char == '"' {
			out = append(out, []rune(string(p.raw[segment:p.pos]))...)
			p.pos++
			value := string(out)
			if !norm.NFC.IsNormalString(value) {
				return "", fail("INVALID_UNICODE")
			}
			return value, nil
		}
		if char == '\\' {
			out = append(out, []rune(string(p.raw[segment:p.pos]))...)
			p.pos++
			escaped, err := p.escape()
			if err != nil {
				return "", err
			}
			out = append(out, escaped...)
			segment = p.pos
			continue
		}
		if char < 0x20 {
			return "", fail("MALFORMED_JSON")
		}
		_, width := utf8.DecodeRune(p.raw[p.pos:])
		p.pos += width
	}
	return "", fail("MALFORMED_JSON")
}

func (p *parser) escape() ([]rune, *Error) {
	if p.pos >= len(p.raw) {
		return nil, fail("MALFORMED_JSON")
	}
	char := p.raw[p.pos]
	p.pos++
	switch char {
	case '"', '\\', '/':
		return []rune{rune(char)}, nil
	case 'b':
		return []rune{'\b'}, nil
	case 'f':
		return []rune{'\f'}, nil
	case 'n':
		return []rune{'\n'}, nil
	case 'r':
		return []rune{'\r'}, nil
	case 't':
		return []rune{'\t'}, nil
	case 'u':
		first, err := p.hexRune()
		if err != nil {
			return nil, err
		}
		if first >= 0xd800 && first <= 0xdbff {
			if p.pos+2 > len(p.raw) || p.raw[p.pos] != '\\' || p.raw[p.pos+1] != 'u' {
				return nil, fail("INVALID_UNICODE")
			}
			p.pos += 2
			second, secondErr := p.hexRune()
			if secondErr != nil || second < 0xdc00 || second > 0xdfff {
				return nil, fail("INVALID_UNICODE")
			}
			return []rune{utf16.DecodeRune(first, second)}, nil
		}
		if first >= 0xdc00 && first <= 0xdfff {
			return nil, fail("INVALID_UNICODE")
		}
		return []rune{first}, nil
	default:
		return nil, fail("MALFORMED_JSON")
	}
}

func (p *parser) hexRune() (rune, *Error) {
	if p.pos+4 > len(p.raw) {
		return 0, fail("MALFORMED_JSON")
	}
	value, err := strconv.ParseUint(string(p.raw[p.pos:p.pos+4]), 16, 16)
	if err != nil {
		return 0, fail("MALFORMED_JSON")
	}
	p.pos += 4
	return rune(value), nil
}

func (p *parser) space() {
	for p.pos < len(p.raw) {
		switch p.raw[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) take(want byte) bool {
	if p.pos < len(p.raw) && p.raw[p.pos] == want {
		p.pos++
		return true
	}
	return false
}

func Encode(value Value) ([]byte, *Error) {
	var output bytes.Buffer
	if err := encode(&output, value, 1); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func encode(output *bytes.Buffer, value Value, depth int) *Error {
	if depth > MaxDepth {
		return fail("DEPTH_LIMIT_EXCEEDED")
	}
	switch item := value.(type) {
	case string:
		if !utf8.ValidString(item) || !norm.NFC.IsNormalString(item) {
			return fail("INVALID_UNICODE")
		}
		quote(output, item)
	case Object:
		keys := make([]string, 0, len(item))
		for key := range item {
			if !isASCII(key) {
				return fail("UNKNOWN_FIELD")
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			quote(output, key)
			output.WriteByte(':')
			if err := encode(output, item[key], depth+1); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	case Array:
		output.WriteByte('[')
		for index, child := range item {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := encode(output, child, depth+1); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	default:
		return fail("WRONG_JSON_TYPE")
	}
	return nil
}

func quote(output *bytes.Buffer, value string) {
	output.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(char)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if char < 0x20 {
				fmt.Fprintf(output, `\u%04x`, char)
			} else {
				output.WriteRune(char)
			}
		}
	}
	output.WriteByte('"')
}

func isASCII(value string) bool {
	for _, char := range value {
		if char > 0x7f {
			return false
		}
	}
	return true
}
