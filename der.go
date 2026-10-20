package main

import (
	"fmt"
	"strings"
)

// Minimal DER decoder for embedded entitlements blobs (type-7 superblob
// slots). Apple's DER encoding serializes the plist as a SEQUENCE of
// alternating key(UTF8String)/value pairs; values are BOOLEAN, INTEGER,
// strings, SEQUENCE (dict) or SET (array).

type derReader struct {
	b []byte
	p int
}

func (d *derReader) tlv() (tag byte, content []byte, ok bool) {
	if d.p+2 > len(d.b) {
		return 0, nil, false
	}
	tag = d.b[d.p]
	d.p++
	l := int(d.b[d.p])
	d.p++
	if l&0x80 != 0 { // long form
		n := l & 0x7f
		if n > 4 || d.p+n > len(d.b) {
			return 0, nil, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(d.b[d.p])
			d.p++
		}
	}
	if d.p+l > len(d.b) {
		return 0, nil, false
	}
	content = d.b[d.p : d.p+l]
	d.p += l
	return tag, content, true
}

// decodeDEREntitlements returns key → rendered value for a DER blob.
func decodeDEREntitlements(data []byte) map[string]string {
	out := map[string]string{}
	d := &derReader{b: data}
	tag, top, ok := d.tlv()
	if !ok || tag != 0x30 { // SEQUENCE
		return out
	}
	d = &derReader{b: top}
	for {
		ktag, key, ok := d.tlv()
		if !ok {
			break
		}
		if ktag != 0x0c && ktag != 0x16 { // UTF8String / IA5String
			continue
		}
		vtag, vcontent, vok := d.tlv() // the value TLV follows the key
		if !vok {
			break
		}
		out[string(key)] = renderDER(vtag, vcontent)
	}
	return out
}

// renderDER turns a DER value into a display string.
func renderDER(tag byte, c []byte) string {
	switch tag {
	case 0x01: // BOOLEAN
		if len(c) > 0 && c[0] != 0 {
			return "true"
		}
		return "false"
	case 0x02: // INTEGER
		var v int64
		for _, b := range c {
			v = v<<8 | int64(b)
		}
		return fmt.Sprintf("%d", v)
	case 0x0c, 0x16, 0x13: // UTF8 / IA5 / PrintableString
		return string(c)
	case 0x30: // SEQUENCE → nested dict
		inner := decodeDEREntitlements(c)
		var parts []string
		for k, v := range inner {
			parts = append(parts, k+"="+v)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case 0x31: // SET → array
		var items []string
		d := &derReader{b: c}
		for {
			t, v, ok := d.tlv()
			if !ok {
				break
			}
			items = append(items, renderDER(t, v))
		}
		return "[" + strings.Join(items, ", ") + "]"
	case 0x04: // OCTET STRING
		return fmt.Sprintf("0x%x", c)
	default:
		return fmt.Sprintf("<tag 0x%02x, %d bytes>", tag, len(c))
	}
}
