package main

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"
)

// Report is the full triage result for one binary.
type Report struct {
	Path         string            `json:"path"`
	Size         int64             `json:"size"`
	Fat          bool              `json:"fat"`
	Archs        []string          `json:"archs"`
	FileType     string            `json:"file_type"`
	Flags        []string          `json:"header_flags"`
	Segments     []SegmentInfo     `json:"segments"`
	Dylibs       []string          `json:"dylibs"`
	Rpaths       []string          `json:"rpaths"`
	InstallName  string            `json:"install_name,omitempty"`
	Imports      []string          `json:"imports,omitempty"`
	Exports      []string          `json:"exports,omitempty"`
	UUID         string            `json:"uuid,omitempty"`
	MinOS        string            `json:"min_os,omitempty"`
	Platform     string            `json:"platform,omitempty"`
	Encrypted    bool              `json:"encrypted,omitempty"`
	WeakDylibs   []string          `json:"weak_dylibs,omitempty"`
	Signature    *SignatureInfo    `json:"signature,omitempty"`
	Entitlements map[string]string `json:"entitlements,omitempty"`
	Strings      []string          `json:"interesting_strings,omitempty"`
	Setuid       bool              `json:"setuid,omitempty"`
	Setgid       bool              `json:"setgid,omitempty"`
	FileMode     string            `json:"file_mode"`
	Findings     []string          `json:"findings"`
}

type SegmentInfo struct {
	Name     string        `json:"name"`
	VMAddr   uint64        `json:"vmaddr"`
	Size     uint64        `json:"size"`
	Prot     string        `json:"prot"`
	Sections []SectionInfo `json:"sections,omitempty"`
}

type SectionInfo struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
}

type SignatureInfo struct {
	Status     string   `json:"status"` // none|adhoc|signed
	Identifier string   `json:"identifier,omitempty"`
	TeamID     string   `json:"team_id,omitempty"`
	Runtime    bool     `json:"hardened_runtime"`
	Notarized  bool     `json:"notarized_staple"`
	HasCMS     bool     `json:"has_cms"`
	EntBytes   int      `json:"entitlement_blob_bytes,omitempty"`
	CDFlags    []string `json:"code_directory_flags,omitempty"`
}

// Analyze parses a Mach-O (thin or fat) and returns the triage report.
func Analyze(path string) (*Report, error) { return analyze(path, true) }

// analyze with full=false skips expensive display-only extraction (strings).
func analyze(path string, full bool) (*Report, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() || st.Size() < 4 {
		return nil, fmt.Errorf("not a mach-o")
	}

	rep := &Report{
		Path:     path,
		Size:     st.Size(),
		FileMode: st.Mode().String(),
		Setuid:   st.Mode()&os.ModeSetuid != 0,
		Setgid:   st.Mode()&os.ModeSetgid != 0,
	}

	if fat, ferr := macho.NewFatFile(fh); ferr == nil {
		defer fat.Close()
		rep.Fat = true
		for _, a := range fat.Arches {
			rep.Archs = append(rep.Archs, cpuName(a.Cpu))
		}
		if a := pickArch(fat); a != nil {
			analyzeThin(rep, a.File, fh, int64(a.Offset), full)
		}
	} else {
		f, err := macho.NewFile(fh)
		if err != nil {
			return nil, err
		}
		rep.Archs = []string{cpuName(f.Cpu)}
		analyzeThin(rep, f, fh, 0, full)
	}

	rep.Findings = deriveFindings(rep)
	return rep, nil
}

// pickArch prefers arm64, then x86_64, else first slice.
func pickArch(fat *macho.FatFile) *macho.FatArch {
	var best *macho.FatArch
	for i := range fat.Arches {
		a := &fat.Arches[i]
		if a.Cpu == macho.CpuArm64 {
			return a
		}
		if a.Cpu == macho.CpuAmd64 {
			best = a
		}
	}
	if best != nil {
		return best
	}
	if len(fat.Arches) > 0 {
		return &fat.Arches[0]
	}
	return nil
}

func analyzeThin(rep *Report, f *macho.File, fh *os.File, base int64, full bool) {
	rep.FileType = typeName(f.Type)
	rep.Flags = flagNames(uint32(f.Flags))

	// group sections under their segment
	segOrder := []string{}
	segMap := map[string]*SegmentInfo{}
	for _, s := range f.Sections {
		si := segMap[s.Seg]
		if si == nil {
			si = &SegmentInfo{Name: s.Seg}
			segMap[s.Seg] = si
			segOrder = append(segOrder, s.Seg)
		}
		si.Sections = append(si.Sections, SectionInfo{
			Name:    s.Name,
			Size:    s.Size,
			Entropy: math.Round(sectionEntropy(s)*100) / 100,
		})
	}
	for _, l := range f.Loads {
		if seg, ok := l.(*macho.Segment); ok {
			if si := segMap[seg.Name]; si != nil {
				si.VMAddr = seg.Addr
				si.Size = seg.Memsz
				si.Prot = protString(uint32(seg.Prot))
			}
		}
	}
	for _, n := range segOrder {
		rep.Segments = append(rep.Segments, *segMap[n])
	}

	if libs, err := f.ImportedLibraries(); err == nil {
		rep.Dylibs = libs
	}

	if f.Symtab != nil {
		var im, ex []string
		for _, s := range f.Symtab.Syms {
			if s.Name == "" || s.Type&0x01 == 0 { // skip non-external
				continue
			}
			if s.Sect == 0 {
				im = append(im, s.Name)
			} else {
				ex = append(ex, s.Name)
			}
		}
		sort.Strings(im)
		sort.Strings(ex)
		rep.Imports = im
		rep.Exports = ex
	}

	for _, l := range f.Loads {
		raw, ok := l.(macho.LoadBytes)
		if !ok || len(raw) < 8 {
			continue
		}
		switch macho.LoadCmd(binary.LittleEndian.Uint32(raw[0:4])) {
		case 0x1c: // LC_RPATH - lc_str: offset@8
			if off := binary.LittleEndian.Uint32(raw[8:12]); int(off) < len(raw) {
				rep.Rpaths = append(rep.Rpaths, cstr(raw[off:]))
			}
		case 0xd: // LC_ID_DYLIB - install name
			if off := binary.LittleEndian.Uint32(raw[8:12]); int(off) < len(raw) {
				rep.InstallName = cstr(raw[off:])
			}
		case 0x1b: // LC_UUID
			if len(raw) >= 24 {
				rep.UUID = fmt.Sprintf("%x", raw[8:24])
			}
		case 0x24, 0x25: // LC_VERSION_MIN_MACOSX / IPHONEOS: version@8
			if len(raw) >= 12 {
				v := binary.LittleEndian.Uint32(raw[8:12])
				rep.MinOS = fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, v&0xff)
			}
		case 0x32: // LC_BUILD_VERSION: platform@8, minos@12
			if len(raw) >= 16 {
				rep.Platform = platformName(binary.LittleEndian.Uint32(raw[8:12]))
				v := binary.LittleEndian.Uint32(raw[12:16])
				rep.MinOS = fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, v&0xff)
			}
		case 0x21, 0x2c: // LC_ENCRYPTION_INFO(_64): cryptid@16
			if len(raw) >= 20 && binary.LittleEndian.Uint32(raw[16:20]) != 0 {
				rep.Encrypted = true
			}
		case 0x80000018: // LC_LOAD_WEAK_DYLIB
			if off := binary.LittleEndian.Uint32(raw[8:12]); int(off) < len(raw) {
				rep.WeakDylibs = append(rep.WeakDylibs, cstr(raw[off:]))
			}
		}
	}

	parseCodeSignature(rep, fh, f, base)
	if full {
		rep.Strings = extractStrings(rep.Path, 60)
	}
}

func sectionEntropy(s *macho.Section) float64 {
	data, err := s.Data()
	if err != nil || len(data) == 0 {
		return 0
	}
	var counts [256]float64
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func cpuName(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm64:
		return "arm64"
	case macho.Cpu386:
		return "i386"
	case macho.CpuArm:
		return "arm"
	}
	return fmt.Sprintf("cpu(%d)", uint32(c))
}

func typeName(t macho.Type) string {
	switch t {
	case macho.TypeObj:
		return "object"
	case macho.TypeExec:
		return "executable"
	case macho.TypeDylib:
		return "dylib"
	case macho.TypeBundle:
		return "bundle"
	case 0xa:
		return "dsym" // MH_DSYM not exported
	}
	return fmt.Sprintf("type(%d)", uint32(t))
}

func flagNames(fl uint32) []string {
	names := []struct {
		b uint32
		n string
	}{
		{macho.FlagNoUndefs, "noundefs"},
		{macho.FlagDyldLink, "dyldlink"},
		{macho.FlagTwoLevel, "twolevel"},
		{macho.FlagPIE, "pie"},
		{macho.FlagAppExtensionSafe, "appext-safe"},
		{0x00100000, "no-reexport"}, // MH_NO_REEXPORTED_DYLIBS
		{0x00000008, "prebound"},    // MH_PREBOUND
	}
	var out []string
	for _, n := range names {
		if fl&n.b != 0 {
			out = append(out, n.n)
		}
	}
	return out
}

func platformName(p uint32) string {
	switch p {
	case 1:
		return "macOS"
	case 2:
		return "iOS"
	case 3:
		return "tvOS"
	case 4:
		return "watchOS"
	case 5:
		return "bridgeOS"
	case 6:
		return "macCatalyst"
	case 7:
		return "iOSSimulator"
	case 8:
		return "tvOSSimulator"
	case 9:
		return "watchOSSimulator"
	case 10:
		return "DriverKit"
	case 11:
		return "visionOS"
	case 12:
		return "visionOSSimulator"
	}
	return fmt.Sprintf("platform(%d)", p)
}

func protString(p uint32) string {
	var r []byte
	if p&1 != 0 {
		r = append(r, 'r')
	}
	if p&2 != 0 {
		r = append(r, 'w')
	}
	if p&4 != 0 {
		r = append(r, 'x')
	}
	return string(r)
}
