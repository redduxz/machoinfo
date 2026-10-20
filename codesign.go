package main

import (
	"debug/macho"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

// Code signature blob magics (big-endian on disk).
const (
	csMagicSuperBlob       = 0xfade0cc0
	csMagicCodeDirectory   = 0xfade0c02
	csMagicBlobWrapper     = 0xfade0b01 // CMS signature
	csMagicEntitlements    = 0xfade7171 // XML plist
	csMagicEntitlementsDER = 0xfade7172
)

// CodeDirectory flag bits we care about.
const (
	csAdhoc        = 0x0002
	csHard         = 0x0100 // kill
	csRuntime      = 0x10000
	csLinkerSigned = 0x20000
	csRequireLV    = 0x2000
)

// superblob index slot types.
const (
	slotCodeDirectory   = 0
	slotEntitlements    = 5
	slotDEREntitlements = 7
	slotSignature       = 0x10000
)

func be32(b []byte, off int) uint32 { return binary.BigEndian.Uint32(b[off:]) }

// parseCodeSignature reads LC_CODE_SIGNATURE and walks the superblob.
func parseCodeSignature(rep *Report, fh *os.File, f *macho.File, base int64) {
	var sigOff, sigSize uint32
	for _, l := range f.Loads {
		raw, ok := l.(macho.LoadBytes)
		if !ok || len(raw) < 16 {
			continue
		}
		if macho.LoadCmd(binary.LittleEndian.Uint32(raw[0:4])) == 0x1d { // LC_CODE_SIGNATURE
			sigOff = binary.LittleEndian.Uint32(raw[8:12])
			sigSize = binary.LittleEndian.Uint32(raw[12:16])
		}
	}
	if sigSize == 0 {
		rep.Signature = &SignatureInfo{Status: "none"}
		return
	}

	buf := make([]byte, sigSize)
	if _, err := fh.ReadAt(buf, base+int64(sigOff)); err != nil {
		rep.Signature = &SignatureInfo{Status: "unreadable"}
		return
	}
	if len(buf) < 12 || be32(buf, 0) != csMagicSuperBlob {
		rep.Signature = &SignatureInfo{Status: "malformed"}
		return
	}

	sig := &SignatureInfo{Status: "adhoc"}
	count := be32(buf, 8)
	var hasCD bool

	for i := uint32(0); i < count; i++ {
		idx := 12 + int(i)*8
		if idx+8 > len(buf) {
			break
		}
		btype := be32(buf, idx)
		boff := be32(buf, idx+4)
		if int(boff)+8 > len(buf) {
			continue
		}
		bmagic := be32(buf, int(boff))
		blen := be32(buf, int(boff)+4)
		if int(boff+blen) > len(buf) {
			blen = uint32(len(buf)) - boff
		}
		blob := buf[boff : boff+blen]

		switch {
		case btype == slotCodeDirectory && bmagic == csMagicCodeDirectory:
			hasCD = true
			parseCodeDirectory(sig, blob)
		case btype == slotEntitlements && bmagic == csMagicEntitlements:
			sig.EntBytes = len(blob) - 8
			rep.Entitlements = decodePlist(blob[8:])
		case btype == slotDEREntitlements && bmagic == csMagicEntitlementsDER:
			sig.EntBytes = len(blob) - 8
			rep.Entitlements = decodeDEREntitlements(blob[8:])
		case btype == slotSignature && bmagic == csMagicBlobWrapper:
			sig.HasCMS = true
		case btype >= 0x1000 && btype < 0x10000:
			// additional blobs (stapled notarization ticket lives here)
			if len(blob) > 16 {
				sig.Notarized = true
			}
		}
	}

	if hasCD && sig.HasCMS {
		sig.Status = "signed"
	} else if hasCD {
		sig.Status = "adhoc"
	}
	rep.Signature = sig
}

// parseCodeDirectory pulls identifier, team id, and security flags.
func parseCodeDirectory(sig *SignatureInfo, b []byte) {
	if len(b) < 44 {
		return
	}
	version := be32(b, 8)
	flags := be32(b, 12)
	identOff := be32(b, 20)

	var cdFlags []string
	if flags&csAdhoc != 0 {
		cdFlags = append(cdFlags, "adhoc")
	}
	if flags&csRuntime != 0 {
		sig.Runtime = true
		cdFlags = append(cdFlags, "runtime")
	}
	if flags&csRequireLV != 0 {
		cdFlags = append(cdFlags, "require-lv")
	}
	if flags&csLinkerSigned != 0 {
		cdFlags = append(cdFlags, "linker-signed")
	}
	if flags&csHard != 0 {
		cdFlags = append(cdFlags, "hard")
	}
	sig.CDFlags = cdFlags

	if int(identOff) < len(b) {
		sig.Identifier = printable(cstr(b[identOff:]))
	}
	// teamOffset exists at version >= 0x20200, offset 48
	if version >= 0x20200 && len(b) > 52 {
		if to := be32(b, 48); to != 0 && int(to) < len(b) {
			sig.TeamID = printable(cstr(b[to:]))
		}
	}
}

// printable returns s only if it's a sane printable ASCII string.
func printable(s string) string {
	if len(s) == 0 || len(s) > 128 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// decodePlist is a minimal plist XML decoder - returns key → rendered value.
func decodePlist(data []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	var stack []map[string]string
	var keyPending string
	var arrDepth int
	var arr []string
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "dict":
				stack = append(stack, map[string]string{})
			case "key":
				var k struct {
					V string `xml:",chardata"`
				}
				dec.DecodeElement(&k, &t)
				keyPending = strings.TrimSpace(k.V)
			case "array":
				arrDepth++
				arr = nil
			case "string", "integer", "date", "data":
				var v struct {
					V string `xml:",chardata"`
				}
				dec.DecodeElement(&v, &t)
				assign(stack, keyPending, v.V, arrDepth, &arr)
				keyPending = ""
			case "true":
				assign(stack, keyPending, "true", arrDepth, &arr)
				keyPending = ""
			case "false":
				assign(stack, keyPending, "false", arrDepth, &arr)
				keyPending = ""
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "dict":
				if len(stack) > 1 {
					inner := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					assign(stack, keyPending, fmt.Sprintf("%v", inner), arrDepth, &arr)
					keyPending = ""
				} else if len(stack) == 1 {
					for k, v := range stack[0] {
						out[k] = v
					}
					stack = nil
				}
			case "array":
				if arrDepth == 1 && keyPending != "" {
					assign(stack, keyPending, "["+strings.Join(arr, ", ")+"]", arrDepth, &arr)
					keyPending = ""
				} else if arrDepth > 0 {
					assign(stack, keyPending, strings.Join(arr, ", "), arrDepth-1, &arr)
				}
				arrDepth--
			}
		}
	}
	return out
}

func assign(stack []map[string]string, key, val string, arrDepth int, arr *[]string) {
	if arrDepth > 0 {
		*arr = append(*arr, val)
		return
	}
	if key == "" || len(stack) == 0 {
		return
	}
	stack[len(stack)-1][key] = val
}
