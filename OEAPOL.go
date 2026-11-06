// OEAPOL — EAPOL/802.1X Analyzer
// OWL Security Tools · Batch 3 (Wireless)
// Author : khaled.s.haddad    Website : owlsec.org
// Language: Go (stdlib only, CGO disabled, static). Authorized testing use only.
//
// This tool performs OFFLINE analysis of wireless protocol artifacts (pcap, hex,
// CSV, IQ, NMEA, LDIF-style captures). It never touches a live radio. All parsing,
// frame dissection, scoring and reporting runs purely on supplied files.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const APPNAME = "OEAPOL"
const SUITE = "Owl Wireless Suite"
const TAGLINE = "EAPOL/802.1X Analyzer"
const SUBLINE = "Sessions · M1–M4 · PMKID · Crackable Pairs · EAP Methods · Identities · Grade"
const CATEGORY = "OWireless"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const BANNER = `
 ██████╗ ███████╗ █████╗ ██████╗  ██████╗ ██╗
██╔═══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██║
██║   ██║█████╗  ███████║██████╔╝██║   ██║██║
██║   ██║██╔══╝  ██╔══██║██╔═══╝ ██║   ██║██║
╚██████╔╝███████╗██║  ██║██║     ╚██████╔╝███████╗
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MAG = "\033[95m"       // magenta — suite name / accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	CYN = CY               // legacy alias
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if noColor {
		fmt.Println()
		return
	}
	fmt.Print("\033[H\033[2J")
}
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MAG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if vlen(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-vlen(s))
}
func vlen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = vlen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && vlen(c) > w[i] {
				w[i] = vlen(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// sectionHead prints a ⬡ heading between two cyan rules.
func sectionHead(s string) {
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
}

// ============================ DATA MODEL ============================

// Severity levels, ordered.
const (
	SevInfo = "INFO"
	SevLow  = "LOW"
	SevMed  = "MEDIUM"
	SevHigh = "HIGH"
	SevCrit = "CRITICAL"
)

// Finding is a single analysis result with MITRE ATT&CK mapping.
type Finding struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Sev   string   `json:"severity"`
	Desc  string   `json:"description"`
	Loc   string   `json:"location"`
	Mitre []string `json:"mitre"`
	Rec   string   `json:"recommendation"`
	Score int      `json:"score"`
}

// Table is a named grid of rows for structured output.
type Table struct {
	Title   string     `json:"title"`
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}

// KV is an ordered key/value pair for summary stats.
type KV struct {
	K string `json:"key"`
	V string `json:"value"`
}

// Report is the unified analysis output every tool produces.
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Category  string    `json:"category"`
	Generated string    `json:"generated"`
	Source    string    `json:"source"`
	Grade     string    `json:"grade"`
	Score     int       `json:"score"`
	Stats     []KV      `json:"stats"`
	Tables    []Table   `json:"tables"`
	Findings  []Finding `json:"findings"`
	Notes     []string  `json:"notes"`
}

func sevRank(s string) int {
	switch s {
	case SevCrit:
		return 4
	case SevHigh:
		return 3
	case SevMed:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}
func sevColor(s string) string {
	switch s {
	case SevCrit:
		return MAG + B
	case SevHigh:
		return R + B
	case SevMed:
		return YLW
	case SevLow:
		return CYN
	default:
		return GY
	}
}

// addFinding appends a finding with a stable auto id when none given.
func (r *Report) add(f Finding) {
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s-%03d", shortTool(), len(r.Findings)+1)
	}
	if f.Score == 0 {
		f.Score = sevRank(f.Sev) * 20
	}
	r.Findings = append(r.Findings, f)
}
func (r *Report) stat(k, v string) { r.Stats = append(r.Stats, KV{k, v}) }
func (r *Report) note(s string)    { r.Notes = append(r.Notes, s) }
func (r *Report) addTable(t Table) { r.Tables = append(r.Tables, t) }

func shortTool() string {
	s := APPNAME
	if len(s) <= 6 {
		return strings.ToUpper(s)
	}
	return strings.ToUpper(s[:6])
}

// grade computes an A+..F posture grade from the finding mix.
func (r *Report) grade() {
	total := 0
	worst := 0
	for _, f := range r.Findings {
		total += sevRank(f.Sev)
		if sevRank(f.Sev) > worst {
			worst = sevRank(f.Sev)
		}
	}
	// Penalty model: weighted by severity density and worst-case.
	pen := total*6 + worst*12
	score := 100 - pen
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	r.Score = score
	r.Grade = gradeLetter(score)
}
func gradeLetter(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func newReport(src string) *Report {
	return &Report{
		Tool:      APPNAME,
		Version:   VERSION,
		Category:  CATEGORY,
		Generated: time.Now().Format("2006-01-02 15:04:05 -0700"),
		Source:    src,
		Stats:     []KV{},
		Tables:    []Table{},
		Findings:  []Finding{},
		Notes:     []string{},
	}
}

// ============================ HELPERS ============================

func macStr(b []byte) string {
	if len(b) < 6 {
		return "??:??:??:??:??:??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ============================ INPUT LOADERS ============================

// CapFrame is one captured frame with metadata.
type CapFrame struct {
	Index    int
	TsSec    uint32
	TsUsec   uint32
	Data     []byte
	OrigLen  uint32
	LinkType uint32
}

const (
	LinkEthernet   = 1
	LinkRaw        = 101
	Link80211      = 105
	Link80211Radio = 127 // radiotap
	LinkPPI        = 192
	LinkBLE        = 251
	Link802154     = 195
	LinkHexEapol   = 0xfffe0001 // internal: hex text / unrecognised file treated as raw EAPOL
)

// loadBytes reads a file (or returns error).
func loadBytes(path string) ([]byte, error) {
	return os.ReadFile(strings.TrimSpace(path))
}

// looksHex reports whether a blob is a hex/whitespace text dump.
func looksHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		case c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' || c == ',':
		case c == 'x' || c == 'X':
		default:
			return false
		}
		n++
		if n > 4096 {
			break
		}
	}
	return true
}

// parseHexDump converts a hex text blob into raw bytes.
func parseHexDump(b []byte) []byte {
	s := string(b)
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, "0X", "")
	var sb strings.Builder
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			sb.WriteRune(c)
		}
	}
	h := sb.String()
	if len(h)%2 == 1 {
		h = h[:len(h)-1]
	}
	out, _ := hex.DecodeString(h)
	return out
}

// parsePcap parses classic libpcap files (both endiannesses).
func parsePcap(b []byte) ([]CapFrame, uint32, error) {
	if len(b) < 24 {
		return nil, 0, errors.New("pcap: too short")
	}
	magic := binary.BigEndian.Uint32(b[0:4])
	var bo binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4, 0xa1b2cd34, 0xa1b23c4d:
		bo = binary.BigEndian
	case 0xd4c3b2a1, 0x34cdb2a1, 0x4d3cb2a1:
		bo = binary.LittleEndian
	default:
		return nil, 0, errors.New("pcap: bad magic")
	}
	linkType := bo.Uint32(b[20:24]) & 0xffff
	nano := magic == 0xa1b23c4d || magic == 0x4d3cb2a1
	var frames []CapFrame
	off := 24
	idx := 0
	for off+16 <= len(b) {
		tsSec := bo.Uint32(b[off : off+4])
		tsUsec := bo.Uint32(b[off+4 : off+8])
		inclLen := bo.Uint32(b[off+8 : off+12])
		origLen := bo.Uint32(b[off+12 : off+16])
		off += 16
		if off+int(inclLen) > len(b) || inclLen > 1<<24 {
			break
		}
		data := make([]byte, inclLen)
		copy(data, b[off:off+int(inclLen)])
		off += int(inclLen)
		if nano {
			tsUsec /= 1000
		}
		frames = append(frames, CapFrame{Index: idx, TsSec: tsSec, TsUsec: tsUsec, Data: data, OrigLen: origLen, LinkType: linkType})
		idx++
	}
	return frames, linkType, nil
}

// parsePcapNG parses a minimal subset of the pcapng format (SHB/IDB/EPB/SPB).
func parsePcapNG(b []byte) ([]CapFrame, uint32, error) {
	if len(b) < 12 || binary.LittleEndian.Uint32(b[0:4]) != 0x0A0D0D0A {
		return nil, 0, errors.New("pcapng: not a section header")
	}
	bo := binary.ByteOrder(binary.LittleEndian)
	if binary.LittleEndian.Uint32(b[8:12]) != 0x1A2B3C4D {
		if binary.BigEndian.Uint32(b[8:12]) == 0x1A2B3C4D {
			bo = binary.BigEndian
		}
	}
	var frames []CapFrame
	var linkType uint32
	var links []uint32 // one link type per interface (IDB), in order
	off := 0
	idx := 0
	for off+12 <= len(b) {
		bt := bo.Uint32(b[off : off+4])
		if bt == 0x0A0D0D0A && off+12 <= len(b) { // new section: byte order and interfaces reset
			if binary.LittleEndian.Uint32(b[off+8:]) == 0x1A2B3C4D {
				bo = binary.LittleEndian
			} else {
				bo = binary.BigEndian
			}
			links = nil
		}
		blen := bo.Uint32(b[off+4 : off+8])
		if blen < 12 || off+int(blen) > len(b) {
			break
		}
		body := b[off+8 : off+int(blen)-4]
		switch bt {
		case 0x00000001: // IDB
			if len(body) >= 2 {
				linkType = uint32(bo.Uint16(body[0:2]))
				links = append(links, linkType)
			}
		case 0x00000006: // EPB
			if len(body) >= 20 {
				capLen := bo.Uint32(body[12:16])
				lt := linkType
				if iface := int(bo.Uint32(body[0:4])); iface < len(links) {
					lt = links[iface]
				}
				us := uint64(bo.Uint32(body[4:8]))<<32 | uint64(bo.Uint32(body[8:12])) // default µs resolution
				if 20+int(capLen) <= len(body) {
					d := make([]byte, capLen)
					copy(d, body[20:20+int(capLen)])
					frames = append(frames, CapFrame{Index: idx, TsSec: uint32(us / 1e6), TsUsec: uint32(us % 1e6), Data: d, OrigLen: capLen, LinkType: lt})
					idx++
				}
			}
		case 0x00000003: // SPB
			if len(body) >= 4 {
				d := make([]byte, len(body)-4)
				copy(d, body[4:])
				frames = append(frames, CapFrame{Index: idx, Data: d, OrigLen: uint32(len(d)), LinkType: linkType})
				idx++
			}
		}
		off += int(blen)
	}
	return frames, linkType, nil
}

// loadCapture resolves pcap/pcapng/hex automatically.
func loadCapture(path string) ([]CapFrame, uint32, error) {
	b, err := loadBytes(path)
	if err != nil {
		return nil, 0, err
	}
	return decodeCapture(b)
}
func decodeCapture(b []byte) ([]CapFrame, uint32, error) {
	if len(b) >= 4 {
		m := binary.BigEndian.Uint32(b[0:4])
		if m == 0xa1b2c3d4 || m == 0xd4c3b2a1 || m == 0xa1b2cd34 || m == 0x34cdb2a1 || m == 0xa1b23c4d || m == 0x4d3cb2a1 {
			return parsePcap(b)
		}
		if binary.LittleEndian.Uint32(b[0:4]) == 0x0A0D0D0A {
			return parsePcapNG(b)
		}
	}
	if looksHex(b) {
		raw := parseHexDump(b)
		if len(raw) > 0 {
			return []CapFrame{{Index: 0, Data: raw, OrigLen: uint32(len(raw)), LinkType: LinkHexEapol}}, LinkHexEapol, nil
		}
	}
	return []CapFrame{{Index: 0, Data: b, OrigLen: uint32(len(b)), LinkType: LinkHexEapol}}, LinkHexEapol, nil
}

// stripRadiotap removes a radiotap header if present, returning the 802.11 body.
func stripRadiotap(f CapFrame) []byte {
	if f.LinkType != Link80211Radio {
		return f.Data
	}
	if len(f.Data) < 4 {
		return f.Data
	}
	l := int(binary.LittleEndian.Uint16(f.Data[2:4]))
	if l <= 0 || l > len(f.Data) {
		return f.Data
	}
	return f.Data[l:]
}

// ============================ EXPORT ENGINE ============================

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Sev) != sevRank(fs[j].Sev) {
			return sevRank(fs[i].Sev) > sevRank(fs[j].Sev)
		}
		return fs[i].ID < fs[j].ID
	})
}

func render(r *Report, format string) string {
	sortFindings(r.Findings)
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func exportTXT(r *Report) string {
	var sb strings.Builder
	w := func(f string, a ...interface{}) { sb.WriteString(fmt.Sprintf(f, a...)) }
	w("%s\n", strings.Repeat("=", 72))
	w("%s  v%s  [%s]\n", r.Tool, r.Version, r.Category)
	w("%s\n", TAGLINE)
	w("Generated : %s\n", r.Generated)
	w("Source    : %s\n", r.Source)
	w("Grade     : %s  (score %d/100)\n", r.Grade, r.Score)
	w("%s\n", strings.Repeat("=", 72))
	if len(r.Stats) > 0 {
		w("\n-- SUMMARY --\n")
		for _, s := range r.Stats {
			w("  %-28s : %s\n", s.K, s.V)
		}
	}
	for _, t := range r.Tables {
		w("\n-- %s --\n", t.Title)
		w("%s\n", strings.Join(t.Headers, " | "))
		for _, row := range t.Rows {
			w("%s\n", strings.Join(row, " | "))
		}
	}
	if len(r.Findings) > 0 {
		w("\n-- FINDINGS (%d) --\n", len(r.Findings))
		for _, f := range r.Findings {
			w("\n[%s] %s  (%s)\n", f.Sev, f.Title, f.ID)
			if f.Loc != "" {
				w("  location : %s\n", f.Loc)
			}
			w("  detail   : %s\n", f.Desc)
			if len(f.Mitre) > 0 {
				w("  mitre    : %s\n", strings.Join(f.Mitre, ", "))
			}
			if f.Rec != "" {
				w("  fix      : %s\n", f.Rec)
			}
		}
	}
	if len(r.Notes) > 0 {
		w("\n-- NOTES --\n")
		for _, n := range r.Notes {
			w("  * %s\n", n)
		}
	}
	w("\n%s\n", strings.Repeat("=", 72))
	w("Authorized testing only. (c) owlsec.org — khaled.s.haddad\n")
	return sb.String()
}

func exportMD(r *Report) string {
	var sb strings.Builder
	w := func(f string, a ...interface{}) { sb.WriteString(fmt.Sprintf(f, a...)) }
	w("# %s report\n\n", r.Tool)
	w("> %s\n\n", TAGLINE)
	w("| Field | Value |\n|---|---|\n")
	w("| Tool | %s v%s |\n", r.Tool, r.Version)
	w("| Category | %s |\n", r.Category)
	w("| Generated | %s |\n", r.Generated)
	w("| Source | %s |\n", mdEsc(r.Source))
	w("| Grade | **%s** (%d/100) |\n", r.Grade, r.Score)
	if len(r.Stats) > 0 {
		w("\n## Summary\n\n| Metric | Value |\n|---|---|\n")
		for _, s := range r.Stats {
			w("| %s | %s |\n", mdEsc(s.K), mdEsc(s.V))
		}
	}
	for _, t := range r.Tables {
		w("\n## %s\n\n", t.Title)
		w("| %s |\n", strings.Join(t.Headers, " | "))
		w("|%s\n", strings.Repeat("---|", len(t.Headers)))
		for _, row := range t.Rows {
			esc := make([]string, len(row))
			for i, c := range row {
				esc[i] = mdEsc(c)
			}
			w("| %s |\n", strings.Join(esc, " | "))
		}
	}
	if len(r.Findings) > 0 {
		w("\n## Findings\n\n")
		for _, f := range r.Findings {
			w("### [%s] %s `%s`\n\n", f.Sev, f.Title, f.ID)
			if f.Loc != "" {
				w("- **Location**: %s\n", mdEsc(f.Loc))
			}
			w("- **Detail**: %s\n", mdEsc(f.Desc))
			if len(f.Mitre) > 0 {
				w("- **MITRE**: %s\n", strings.Join(f.Mitre, ", "))
			}
			if f.Rec != "" {
				w("- **Fix**: %s\n", mdEsc(f.Rec))
			}
			w("\n")
		}
	}
	if len(r.Notes) > 0 {
		w("\n## Notes\n\n")
		for _, n := range r.Notes {
			w("- %s\n", mdEsc(n))
		}
	}
	return sb.String()
}
func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func exportJSON(r *Report) string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func exportCSV(r *Report) string {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.Write([]string{"type", "id", "severity", "title", "location", "mitre", "detail", "recommendation"})
	for _, f := range r.Findings {
		cw.Write([]string{"finding", f.ID, f.Sev, f.Title, f.Loc, strings.Join(f.Mitre, ";"), f.Desc, f.Rec})
	}
	for _, t := range r.Tables {
		for _, row := range t.Rows {
			rec := []string{"row:" + t.Title}
			rec = append(rec, row...)
			cw.Write(rec)
		}
	}
	cw.Flush()
	return buf.String()
}

// exportSARIF produces SARIF 2.1.0 with findings as results.
func exportSARIF(r *Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string                 `json:"id"`
		Name             string                 `json:"name"`
		ShortDescription sarifMsg               `json:"shortDescription"`
		FullDescription  sarifMsg               `json:"fullDescription"`
		Properties       map[string]interface{} `json:"properties,omitempty"`
		HelpURI          string                 `json:"helpUri,omitempty"`
	}
	type sarifLoc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string                 `json:"ruleId"`
		Level      string                 `json:"level"`
		Message    sarifMsg               `json:"message"`
		Locations  []sarifLoc             `json:"locations,omitempty"`
		Properties map[string]interface{} `json:"properties,omitempty"`
	}
	level := func(s string) string {
		switch s {
		case SevCrit, SevHigh:
			return "error"
		case SevMed:
			return "warning"
		case SevLow:
			return "note"
		default:
			return "none"
		}
	}
	ruleSet := map[string]sarifRule{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.ID]; !ok {
			rule := sarifRule{
				ID:               f.ID,
				Name:             strings.ReplaceAll(f.Title, " ", ""),
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: f.Desc},
				HelpURI:          "https://owlsec.org",
				Properties:       map[string]interface{}{"mitre": f.Mitre, "severity": f.Sev},
			}
			ruleSet[f.ID] = rule
			rules = append(rules, rule)
		}
		res := sarifResult{
			RuleID:     f.ID,
			Level:      level(f.Sev),
			Message:    sarifMsg{Text: f.Desc},
			Properties: map[string]interface{}{"mitre": f.Mitre, "recommendation": f.Rec},
		}
		if f.Loc != "" {
			var l sarifLoc
			l.PhysicalLocation.ArtifactLocation.URI = f.Loc
			res.Locations = append(res.Locations, l)
		}
		results = append(results, res)
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           r.Tool,
						"version":        r.Version,
						"informationUri": "https://owlsec.org",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ============================ HOW TO USE SCREEN ============================
//
// Domain code must define these package-level variables:
//   howtoWarning string      — the LEGAL & ETHICAL WARNING text
//   howtoSteps   []string    — numbered HOW TO USE steps
//   howtoNav     []string    — NAVIGATION key descriptions
//   howtoReq     []string    — REQUIREMENTS list
//   howtoNotes   []string    — feature / protocol notes
// and a func analyze(src string, demo bool) *Report.

func showHowto() {
	clear()
	banner()
	fmt.Println()
	fmt.Println("  " + col("╔══════════════════════════════════════════════════════════════╗", DR))
	fmt.Println("  " + col("║  ", DR) + col("HOW TO USE — "+APPNAME, CY+B) + col(strings.Repeat(" ", max(0, 48-len(APPNAME)))+"║", DR))
	fmt.Println("  " + col("╚══════════════════════════════════════════════════════════════╝", DR))

	sectionHead("LEGAL & ETHICAL WARNING")
	for _, l := range wrapText(howtoWarning, 66) {
		fmt.Println("  " + col(l, YLW))
	}

	sectionHead("HOW TO USE")
	for i, s := range howtoSteps {
		fmt.Printf("   %s %s\n", col(fmt.Sprintf("%2d.", i+1), CY+B), col(s, W))
	}

	sectionHead("REQUIREMENTS")
	for _, s := range howtoReq {
		fmt.Println("   " + col("- ", DR) + col(s, GY))
	}

	sectionHead("FEATURE / PROTOCOL NOTES")
	for _, s := range howtoNotes {
		for _, l := range wrapText(s, 64) {
			fmt.Println("   " + col(l, W))
		}
	}
	fmt.Println()
	line(64)
	fmt.Println("  " + col("MITRE ATT&CK : ", DIM) + col(MITREID, R))
	fmt.Println("  " + col("Export formats: txt · md · json · csv · sarif", GY))
}

// printHowto renders the same content for the --howto CLI flag (no screen clear).
func printHowto() {
	savedNo := noColor
	_ = savedNo
	fmt.Println(APPNAME + " — HOW TO USE")
	fmt.Println(strings.Repeat("=", 64))
	fmt.Println("\n[LEGAL & ETHICAL WARNING]")
	for _, l := range wrapText(howtoWarning, 70) {
		fmt.Println("  " + l)
	}
	fmt.Println("\n[HOW TO USE]")
	for i, s := range howtoSteps {
		fmt.Printf("  %2d. %s\n", i+1, s)
	}
	fmt.Println("\n[NAVIGATION]")
	for _, s := range howtoNav {
		fmt.Println("  * " + s)
	}
	fmt.Println("\n[REQUIREMENTS]")
	for _, s := range howtoReq {
		fmt.Println("  - " + s)
	}
	fmt.Println("\n[FEATURE / PROTOCOL NOTES]")
	for _, s := range howtoNotes {
		for _, l := range wrapText(s, 70) {
			fmt.Println("  " + l)
		}
	}
	fmt.Println("\nMITRE ATT&CK: " + MITREID)
	fmt.Println("Export formats: txt md json csv sarif")
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) == 0 {
		lines = []string{""}
	}
	return lines
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ============================ GENERIC HANDLERS ============================

func showReport(r *Report) {
	sortFindings(r.Findings)
	for _, s := range r.Stats {
		info(s.K + " : " + s.V)
	}
	for _, t := range r.Tables {
		if len(t.Rows) == 0 {
			continue
		}
		sectionHead(t.Title)
		shown := t.Rows
		if len(shown) > 40 {
			shown = shown[:40]
		}
		table(t.Headers, shown)
		if len(t.Rows) > 40 {
			info(fmt.Sprintf("... %d more rows (use --output for full export)", len(t.Rows)-40))
		}
	}
	if len(r.Findings) > 0 {
		sectionHead(fmt.Sprintf("FINDINGS (%d)", len(r.Findings)))
		for _, f := range r.Findings {
			fmt.Printf("   %s %s %s\n", col("["+f.Sev+"]", sevColor(f.Sev)), col(f.Title, W), col("("+f.ID+")", GY))
			fmt.Println("      " + col(f.Desc, GY))
			if len(f.Mitre) > 0 {
				fmt.Println("      " + col("MITRE: "+strings.Join(f.Mitre, ", "), DIM))
			}
		}
	}
	sectionHead("POSTURE GRADE")
	gc := GRN + B
	if r.Score < 70 {
		gc = YLW
	}
	if r.Score < 60 {
		gc = R + B
	}
	fmt.Println("   " + col(r.Grade, gc) + col(fmt.Sprintf("   (%d/100)", r.Score), GY))
}

func handleRunFile() {
	p := prompt("capture / input file path")
	if p == "" {
		warnMsg("no path given")
		return
	}
	r := analyze(p, false, "")
	lastReport = r
	showReport(r)
}
func handleRunDemo() {
	info("running self-contained synthetic demo...")
	r := analyze("", true, "")
	lastReport = r
	showReport(r)
}
func handleExport() {
	r := lastReport
	if r == nil {
		p := prompt("input file (blank = demo)")
		if p == "" {
			r = analyze("", true, "")
		} else {
			r = analyze(p, false, "")
		}
	}
	f := prompt("format [txt/md/json/csv/sarif]")
	if f == "" {
		f = "txt"
	}
	out := prompt("output file (blank = screen)")
	data := render(r, f)
	if out == "" {
		fmt.Println(data)
	} else {
		if err := os.WriteFile(out, []byte(data), 0644); err != nil {
			errMsg("write failed: " + err.Error())
		} else {
			okMsg("wrote " + out + " (" + f + ")")
		}
	}
}
func handleHowto() { showHowto() }

var lastReport *Report

// menuEntry binds a label to a handler for the interactive TUI.
type menuEntry struct {
	Label string
	Desc  string
	Fn    func()
}

func interactive() {
	for {
		items := make([]menuItem, len(menuDef))
		for i, m := range menuDef {
			items[i] = menuItem{key: fmt.Sprintf("%02d", i+1), name: m.Label, desc: m.Desc, clr: CY + B}
		}
		ch := menu(TAGLINE, items)
		switch ch {
		case "00", "0", "q", "quit", "exit":
			clear()
			banner()
			okMsg("Session closed. Stay ethical. — owlsec.org")
			return
		case "":
			continue
		case "h", "H", "help", "?":
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(ch)
		if err != nil || n < 1 || n > len(menuDef) {
			errMsg("invalid selection")
			pause()
			continue
		}
		clear()
		banner()
		menuDef[n-1].Fn()
		pause()
	}
}

// ============================ CLI / MAIN ============================

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("DESCRIPTION")
	fmt.Println("    EAPOL / 802.1X analyzer. Rebuilds WPA/WPA2 4-way handshakes (M1-M4),")
	fmt.Println("    finds crackable handshake pairs and PMKIDs, lists EAP methods and leaked")
	fmt.Println("    identities, flags weak EAP (MD5, LEAP, MSCHAPv2), TKIP and failed-auth bursts.")
	fmt.Println()
	sec("INPUT")
	fmt.Println("    --input FILE     pcap / pcapng (802.11, radiotap, PPI, Ethernet/VLAN, SLL) or EAPOL hex")
	fmt.Println("    --pcap FILE      alias for --input")
	fmt.Println("    --path FILE      alias for --input")
	fmt.Println("    --target MAC     only frames whose AP/client/BSSID contains MAC (substring)")
	fmt.Println()
	sec("REPORTING")
	fmt.Println("    --format FMT     txt | md | json | csv | sarif (default txt)")
	fmt.Println("    --output FILE    write report to FILE instead of stdout")
	fmt.Println("    --no-color       disable ANSI colors")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo           run built-in synthetic dataset")
	fmt.Println("    --howto          print the HOW TO USE guide (legal, steps, protocol notes)")
	fmt.Println("    --selftest       run built-in self-tests (exit 0/1)")
	fmt.Println("    --version        print version and exit")
	fmt.Println("    -h, --help       show this help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --input handshake.pcapng")
	fmt.Println("    " + APPNAME + " --input wifi.pcap --target aa:bb:cc:11:22:33")
	fmt.Println("    " + APPNAME + " --input wired-8021x.pcap --format json --output eapol.json")
	fmt.Println("    " + APPNAME + " --input wifi.pcap --format sarif --output eapol.sarif")
	fmt.Println("    " + APPNAME + " --input frames.hex")
	fmt.Println("    " + APPNAME + " --demo --format md")
	fmt.Println()
	fmt.Println("  " + col("MITRE", CY+B) + "  " + MITREID)
	line(66)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func main() {
	flag.Usage = usage
	versionF := flag.Bool("version", false, "print version")
	howtoF := flag.Bool("howto", false, "print HOW TO USE guide")
	demoF := flag.Bool("demo", false, "run synthetic demo")
	formatF := flag.String("format", "txt", "output format")
	outputF := flag.String("output", "", "output file")
	inputF := flag.String("input", "", "input file")
	pcapF := flag.String("pcap", "", "capture file")
	targetF := flag.String("target", "", "target selector")
	pathF := flag.String("path", "", "input file alias")
	ncF := flag.Bool("no-color", false, "disable colors")
	selfF := flag.Bool("selftest", false, "run self-tests")
	flag.Parse()

	if *ncF {
		noColor = true
	}
	if *versionF {
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
		fmt.Printf("Author : %s\nWebsite: %s\n", AUTHOR, WEBSITE)
		fmt.Println("Build  : Go stdlib, static (CGO disabled)")
		return
	}
	if *howtoF {
		printHowto()
		return
	}
	if *selfF {
		if !runSelfTest() {
			os.Exit(1)
		}
		return
	}
	src := firstNonEmpty(*inputF, *pcapF, *pathF)
	if src == "" && !*demoF {
		interactive()
		return
	}
	var r *Report
	if *demoF {
		r = analyze("", true, *targetF)
	} else {
		r = analyze(src, false, *targetF)
	}
	if strings.TrimSpace(*targetF) != "" {
		r.note("MAC filter: " + *targetF)
	}
	out := render(r, *formatF)
	if *outputF != "" {
		if err := os.WriteFile(*outputF, []byte(out), 0644); err != nil {
			fmt.Fprintln(os.Stderr, "write error:", err)
			os.Exit(1)
		}
		fmt.Printf("%s: wrote %s report to %s\n", APPNAME, *formatF, *outputF)
		return
	}
	fmt.Print(out)
	for _, f := range r.Findings {
		if f.Sev == SevCrit || f.Sev == SevHigh {
			os.Exit(3)
		}
	}
}

// rsnAKMName names an RSN AKM suite selector (00-0F-AC:n).
func rsnAKMName(sel uint32) string {
	switch sel & 0xFF {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE (WPA3)"
	case 9:
		return "FT-SAE"
	case 11:
		return "802.1X-Suite-B"
	case 12:
		return "802.1X-Suite-B-192"
	case 18:
		return "OWE"
	}
	return fmt.Sprintf("akm-%d", sel&0xFF)
}

// ============================ OEAPOL DOMAIN ENGINE ============================
// Offline EAPOL / IEEE 802.1X analyzer. Extracts validated EAPOL PDUs from
// 802.11 (radiotap/PPI, QoS/4-address aware), Ethernet/VLAN and SLL captures,
// decodes EAP (methods, identities) and EAPOL-Key frames in full (nonce, MIC,
// key data, PMKID KDE), groups them into authenticator↔supplicant sessions,
// and reports offline-crackable material, failed-auth bursts and weak EAP.
// Reads pcap (EAPOL frames) or hex.

const MITREID = "T1557 / T1040 (authentication capture & analysis, authorized labs)"

// EAPOL packet types (IEEE 802.1X-2010).
var eapolType = map[int]string{
	0: "EAP-Packet",
	1: "EAPOL-Start",
	2: "EAPOL-Logoff",
	3: "EAPOL-Key",
	4: "EAPOL-Encapsulated-ASF-Alert",
	5: "EAPOL-MKA",
	6: "EAPOL-Announcement (Generic)",
	7: "EAPOL-Announcement (Specific)",
	8: "EAPOL-Announcement-Req",
}

// EAP codes (RFC 3748).
var eapCode = map[int]string{1: "Request", 2: "Response", 3: "Success", 4: "Failure", 5: "Initiate", 6: "Finish"}

// EAP method types (IANA EAP registry subset).
type eapMethod struct {
	Name string
	Weak bool
	Note string
}

var eapTypes = map[int]eapMethod{
	1:  {"Identity", false, "username disclosed in cleartext"},
	2:  {"Notification", false, ""},
	3:  {"Legacy NAK", false, "method negotiation"},
	4:  {"MD5-Challenge", true, "offline dictionary attack; no mutual auth, no key material"},
	5:  {"OTP", false, "one-time password"},
	6:  {"GTC", true, "cleartext token inside tunnel; risky if tunnel not validated"},
	9:  {"RSA Public Key", false, ""},
	13: {"EAP-TLS", false, "mutual cert auth — strong"},
	17: {"LEAP", true, "Cisco LEAP; MS-CHAPv1 based, broken (asleap)"},
	18: {"EAP-SIM", true, "GSM SIM; A3/A8 weaknesses"},
	21: {"EAP-TTLS", false, "tunneled; secure if server cert validated"},
	23: {"EAP-AKA", false, "UMTS AKA"},
	25: {"PEAP", false, "tunneled MSCHAPv2; secure only if server cert validated"},
	26: {"EAP-MSCHAPv2", true, "MSCHAPv2; crackable (chapcrack) if tunnel absent/invalid"},
	29: {"EAP-MSCHAPv2 (legacy)", true, "legacy"},
	43: {"EAP-FAST", false, "PAC-based; anonymous provisioning risky"},
	47: {"EAP-PSK", false, ""},
	50: {"EAP-AKA'", false, "improved AKA"},
	52: {"EAP-PWD", false, "password-authenticated; dragonfly"},
	53: {"EAP-EKE", false, ""},
	54: {"EAP-PT", false, ""},
	55: {"TEAP", false, "tunnel EAP"},
}

// eapolPkt is one validated EAPOL PDU with its link-layer addressing.
type eapolPkt struct {
	Index   int
	Time    time.Time
	Src     string // transmitter MAC
	Dst     string // receiver MAC
	BSSID   string // 802.11 BSSID ("" on wired captures)
	Via     string // ethernet | 802.11 | sll | raw
	Payload []byte // starts at the EAPOL version byte
}

// EapolFrame is a fully decoded EAPOL PDU.
type EapolFrame struct {
	Index   int
	Src     string
	Dst     string
	BSSID   string
	Version int
	Type    int
	TypeStr string
	Length  int
	// EAP (type 0)
	EapCode  int
	EapID    int
	EapType  int
	EapMeth  string
	Identity string
	// EAPOL-Key (type 3)
	KeyDescType int
	KeyInfo     uint16
	KeyMIC      bool
	KeyACK      bool
	KeyInstall  bool
	KeyPairwise bool
	KeySecure   bool
	KeyEncr     bool
	KeyError    bool
	KeyVer      int
	ReplayCtr   uint64
	Nonce       []byte
	NonceZero   bool
	MICLen      int
	KeyData     []byte
	PMKID       []byte
	HandshakeM  int // 1..4, 0 = group key / unknown
}

// isEapol validates an EAPOL header so arbitrary bytes are never mistaken
// for EAPOL (the old parser decoded every packet in a capture as EAPOL).
func isEapol(b []byte) bool {
	if len(b) < 4 || b[0] < 1 || b[0] > 3 || b[1] > 8 {
		return false
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	return l <= len(b)-4 && (b[1] != 3 || l >= 77)
}

func macOf(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return macStr(b[:6])
}

// dot11HeaderLen computes the MAC header length of a data frame.
func dot11HeaderLen(b []byte) int {
	fc := binary.LittleEndian.Uint16(b)
	n := 24
	if fc&0x0300 == 0x0300 {
		n += 6 // 4-address (WDS / mesh)
	}
	if (fc>>2)&3 == 2 && (fc>>4)&0x8 != 0 {
		n += 2 // QoS control
		if fc&0x8000 != 0 {
			n += 4 // HT control
		}
	}
	return n
}

// extractEapol finds EAPOL PDUs in captured frames of any supported link type.
func extractEapol(frames []CapFrame) []eapolPkt {
	var out []eapolPkt
	for _, f := range frames {
		d := f.Data
		p := eapolPkt{Index: f.Index, Time: time.Unix(int64(f.TsSec), int64(f.TsUsec)*1000)}
		switch f.LinkType {
		case LinkEthernet:
			if len(d) < 14 {
				continue
			}
			et, off := binary.BigEndian.Uint16(d[12:]), 14
			for (et == 0x8100 || et == 0x88a8) && len(d) >= off+4 {
				et, off = binary.BigEndian.Uint16(d[off+2:]), off+4
			}
			if et != 0x888e {
				continue
			}
			p.Dst, p.Src, p.Via, p.Payload = macOf(d[0:]), macOf(d[6:]), "ethernet", d[off:]
		case 113: // Linux cooked
			if len(d) < 16 || binary.BigEndian.Uint16(d[14:]) != 0x888e {
				continue
			}
			p.Src, p.Via, p.Payload = macOf(d[6:]), "sll", d[16:]
		case Link80211, Link80211Radio, LinkPPI:
			if f.LinkType == Link80211Radio {
				d = stripRadiotap(f)
			} else if f.LinkType == LinkPPI && len(d) >= 4 {
				if l := int(binary.LittleEndian.Uint16(d[2:4])); l > 0 && l <= len(d) {
					d = d[l:]
				}
			}
			if len(d) < 24 {
				continue
			}
			fc := binary.LittleEndian.Uint16(d)
			if (fc>>2)&3 != 2 || fc&0x4000 != 0 || (fc>>4)&0x4 != 0 { // data, unprotected, carries payload
				continue
			}
			hl := dot11HeaderLen(d)
			if len(d) < hl+8 || !bytes.Equal(d[hl:hl+8], []byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e}) {
				continue
			}
			a1, a2, a3 := macOf(d[4:]), macOf(d[10:]), macOf(d[16:])
			switch fc & 0x0300 {
			case 0x0100: // to DS: STA → AP
				p.BSSID, p.Src, p.Dst = a1, a2, a3
			case 0x0200: // from DS: AP → STA
				p.BSSID, p.Src, p.Dst = a2, a3, a1
			default:
				p.BSSID, p.Src, p.Dst = a3, a2, a1
			}
			p.Via, p.Payload = "802.11", d[hl+8:]
		case LinkHexEapol: // hex / raw input — try as-is, then behind LLC/SNAP or Ethernet
			switch {
			case len(d) >= 8 && bytes.Equal(d[:8], []byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e}):
				d = d[8:]
			case len(d) >= 14 && d[12] == 0x88 && d[13] == 0x8e:
				p.Dst, p.Src, d = macOf(d[0:]), macOf(d[6:]), d[14:]
			}
			p.Via, p.Payload = "raw", d
		default:
			continue // other link types cannot carry EAPOL
		}
		if isEapol(p.Payload) {
			p.Payload = p.Payload[:4+int(binary.BigEndian.Uint16(p.Payload[2:4]))]
			out = append(out, p)
		}
	}
	return out
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// parseEapol decodes a validated EAPOL PDU.
func parseEapol(p eapolPkt) EapolFrame {
	b := p.Payload
	f := EapolFrame{Index: p.Index, Src: p.Src, Dst: p.Dst, BSSID: p.BSSID, Version: int(b[0]), Type: int(b[1]),
		Length: int(binary.BigEndian.Uint16(b[2:4]))}
	f.TypeStr = eapolType[f.Type]
	if f.TypeStr == "" {
		f.TypeStr = fmt.Sprintf("Type-%d", f.Type)
	}
	body := b[4:]
	switch f.Type {
	case 0:
		if len(body) >= 4 {
			f.EapCode, f.EapID = int(body[0]), int(body[1])
			el := int(binary.BigEndian.Uint16(body[2:4]))
			if el > len(body) {
				el = len(body)
			}
			if (f.EapCode == 1 || f.EapCode == 2) && el >= 5 {
				f.EapType = int(body[4])
				if m, ok := eapTypes[f.EapType]; ok {
					f.EapMeth = m.Name
				} else {
					f.EapMeth = fmt.Sprintf("EAP-Type-%d", f.EapType)
				}
				if f.EapType == 1 && f.EapCode == 2 && el > 5 {
					f.Identity = strings.Map(func(r rune) rune {
						if r < 0x20 || r > 0x7e {
							return '.'
						}
						return r
					}, string(body[5:el]))
				}
			}
		}
	case 3:
		if len(body) < 77 {
			break
		}
		f.KeyDescType = int(body[0])
		f.KeyInfo = binary.BigEndian.Uint16(body[1:3])
		f.KeyVer = int(f.KeyInfo & 0x07)
		f.KeyPairwise = f.KeyInfo&0x0008 != 0
		f.KeyInstall = f.KeyInfo&0x0040 != 0
		f.KeyACK = f.KeyInfo&0x0080 != 0
		f.KeyMIC = f.KeyInfo&0x0100 != 0
		f.KeySecure = f.KeyInfo&0x0200 != 0
		f.KeyError = f.KeyInfo&0x0400 != 0
		f.KeyEncr = f.KeyInfo&0x1000 != 0
		f.ReplayCtr = binary.BigEndian.Uint64(body[5:13])
		f.Nonce = body[13:45]
		f.NonceZero = allZero(f.Nonce)
		// MIC is 16 bytes, or 24 for the SHA-384 AKMs; pick the one whose
		// key-data length field matches the remaining bytes.
		for _, ml := range []int{16, 24} {
			at := 77 + ml
			if len(body) >= at+2 {
				dl := int(binary.BigEndian.Uint16(body[at:]))
				if at+2+dl == len(body) {
					f.MICLen, f.KeyData = ml, body[at+2:]
					break
				}
			}
		}
		if f.MICLen == 0 && len(body) >= 95 {
			f.MICLen = 16
			dl := int(binary.BigEndian.Uint16(body[93:]))
			if 95+dl <= len(body) {
				f.KeyData = body[95 : 95+dl]
			}
		}
		if !f.KeyEncr {
			for i := 0; i+2 <= len(f.KeyData); {
				t, l := f.KeyData[i], int(f.KeyData[i+1])
				if i+2+l > len(f.KeyData) {
					break
				}
				v := f.KeyData[i+2 : i+2+l]
				if t == 0xdd && l >= 20 && bytes.Equal(v[:4], []byte{0x00, 0x0f, 0xac, 0x04}) && !allZero(v[4:20]) {
					f.PMKID = v[4:20]
				}
				i += 2 + l
			}
		}
		f.HandshakeM = classifyHandshake(f)
	}
	return f
}

// classifyHandshake maps Key Information bits (plus the nonce) to M1..M4.
// M2 and M4 share their flags on many stacks; M4 carries an all-zero nonce.
func classifyHandshake(f EapolFrame) int {
	if !f.KeyPairwise {
		return 0 // group-key handshake
	}
	switch {
	case f.KeyACK && !f.KeyMIC:
		return 1
	case f.KeyACK && f.KeyMIC && f.KeyInstall:
		return 3
	case !f.KeyACK && f.KeyMIC && (f.KeySecure || f.NonceZero) && !(len(f.KeyData) > 0 && !f.NonceZero):
		return 4
	case !f.KeyACK && f.KeyMIC:
		return 2
	}
	return 0
}

// bssInfo is what a beacon / probe response says about a network.
type bssInfo struct {
	SSID string
	AKMs []string
}

// beaconAKMs reads SSID and RSN AKM suites from beacons / probe responses.
func beaconAKMs(frames []CapFrame) map[string]bssInfo {
	out := map[string]bssInfo{}
	for _, f := range frames {
		if f.LinkType != Link80211 && f.LinkType != Link80211Radio && f.LinkType != LinkPPI {
			continue
		}
		d := f.Data
		if f.LinkType == Link80211Radio {
			d = stripRadiotap(f)
		} else if f.LinkType == LinkPPI && len(d) >= 4 {
			if l := int(binary.LittleEndian.Uint16(d[2:4])); l > 0 && l <= len(d) {
				d = d[l:]
			}
		}
		if len(d) < 36 {
			continue
		}
		fc := binary.LittleEndian.Uint16(d)
		if (fc>>2)&3 != 0 || ((fc>>4)&0xf != 8 && (fc>>4)&0xf != 5) {
			continue
		}
		bssid := macOf(d[16:])
		info := bssInfo{}
		for i := 36; i+2 <= len(d); {
			id, l := d[i], int(d[i+1])
			if i+2+l > len(d) {
				break
			}
			v := d[i+2 : i+2+l]
			switch id {
			case 0:
				info.SSID = string(v)
			case 48: // RSN: ver(2) group(4) npair(2) pair(4n) nakm(2) akm(4n)
				if len(v) >= 8 {
					np := int(binary.LittleEndian.Uint16(v[6:]))
					o := 8 + 4*np
					if len(v) >= o+2 {
						na := int(binary.LittleEndian.Uint16(v[o:]))
						for k := 0; k < na && len(v) >= o+2+4*(k+1); k++ {
							s := v[o+2+4*k : o+6+4*k]
							info.AKMs = append(info.AKMs, rsnAKMName(uint32(s[3])))
						}
					}
				}
			}
			i += 2 + l
		}
		if old, ok := out[bssid]; !ok || len(old.AKMs) == 0 {
			out[bssid] = info
		}
	}
	return out
}

// session is one authenticator ↔ supplicant exchange.
type session struct {
	AP, STA  string
	Frames   []EapolFrame
	M        [5]int
	PMKID    []byte
	KeyVers  map[int]bool
	EapFail  int
	EapOK    int
	Methods  map[int]bool
	Pairs    []string // crackable message pairs, e.g. "M1+M2 (rc 1)"
	M3Resend int
}

func sessionKey(f EapolFrame) (string, string) {
	// The authenticator sends EAP-Requests and Key frames with ACK set.
	switch {
	case f.Type == 3 && f.KeyACK, f.Type == 0 && (f.EapCode == 1 || f.EapCode == 3 || f.EapCode == 4):
		return f.Src, f.Dst
	case f.Type == 1: // EAPOL-Start comes from the supplicant
		return f.Dst, f.Src
	}
	return f.Dst, f.Src
}

func buildSessions(frames []EapolFrame) []*session {
	m := map[string]*session{}
	var order []string
	for _, f := range frames {
		if f.Type == 1 || f.Type == 2 {
			continue // EAPOL-Start / Logoff go to the PAE group address, not a peer
		}
		ap, sta := sessionKey(f)
		if f.BSSID != "" {
			ap = f.BSSID
		}
		k := ap + "|" + sta
		s := m[k]
		if s == nil {
			s = &session{AP: ap, STA: sta, KeyVers: map[int]bool{}, Methods: map[int]bool{}}
			m[k] = s
			order = append(order, k)
		}
		s.Frames = append(s.Frames, f)
		switch f.Type {
		case 3:
			if f.HandshakeM > 0 {
				s.M[f.HandshakeM]++
			}
			s.KeyVers[f.KeyVer] = true
			if f.PMKID != nil && s.PMKID == nil {
				s.PMKID = f.PMKID
			}
		case 0:
			switch f.EapCode {
			case 3:
				s.EapOK++
			case 4:
				s.EapFail++
			case 1, 2:
				s.Methods[f.EapType] = true
			}
		}
	}
	var out []*session
	for _, k := range order {
		s := m[k]
		// crackable pairs: M1/M2 share a replay counter; M3 = M2's counter + 1
		var m1, m2, m3 []EapolFrame
		for _, f := range s.Frames {
			switch f.HandshakeM {
			case 1:
				m1 = append(m1, f)
			case 2:
				m2 = append(m2, f)
			case 3:
				m3 = append(m3, f)
			}
		}
		seen := map[string]bool{}
		for _, b := range m2 {
			for _, a := range m1 {
				if a.ReplayCtr == b.ReplayCtr && !seen["12"] {
					s.Pairs, seen["12"] = append(s.Pairs, fmt.Sprintf("M1+M2 (replay %d)", a.ReplayCtr)), true
				}
			}
			for _, c := range m3 {
				if c.ReplayCtr == b.ReplayCtr+1 && !seen["23"] {
					s.Pairs, seen["23"] = append(s.Pairs, fmt.Sprintf("M2+M3 (replay %d)", c.ReplayCtr)), true
				}
			}
		}
		anon := map[string]int{}
		for _, c := range m3 {
			anon[string(c.Nonce)]++
		}
		for _, n := range anon {
			if n > 1 {
				s.M3Resend += n - 1
			}
		}
		out = append(out, s)
	}
	return out
}

// akmClass summarises a network's AKMs: "psk", "sae", "8021x", "owe" or "".
func akmClass(akms []string) string {
	has := func(p string) bool {
		for _, a := range akms {
			if strings.Contains(a, p) {
				return true
			}
		}
		return false
	}
	switch {
	case has("PSK") && !has("SAE"):
		return "psk"
	case has("PSK") && has("SAE"):
		return "psk+sae" // WPA2/WPA3 transition: PSK clients stay crackable
	case has("SAE"):
		return "sae"
	case has("OWE"):
		return "owe"
	case has("802.1X"):
		return "8021x"
	}
	return ""
}

func analyzeFrames(r *Report, capFrames []CapFrame, filter string) {
	pkts := extractEapol(capFrames)
	nets := beaconAKMs(capFrames)
	var frames []EapolFrame
	for _, p := range pkts {
		f := parseEapol(p)
		if filter != "" && !strings.Contains(strings.ToLower(f.Src+f.Dst+f.BSSID), strings.ToLower(filter)) {
			continue
		}
		frames = append(frames, f)
	}
	r.stat("captured frames", strconv.Itoa(len(capFrames)))
	r.stat("EAPOL frames", strconv.Itoa(len(frames)))
	if len(frames) == 0 {
		r.add(Finding{ID: "EAPOL-NONE", Title: "No EAPOL frames", Sev: SevInfo, Desc: "No valid 802.1X/EAPOL PDUs were found in the input (802.11 data, Ethernet/VLAN, Linux SLL or raw EAPOL are recognised).", Mitre: []string{}})
		return
	}
	ft := Table{Title: "EAPOL/EAP Frames", Headers: []string{"#", "From", "To", "Type", "EAP", "Method / HS", "KeyVer", "Replay", "Notes"}}
	for _, f := range frames {
		code, what, kv, rc, notes := "", f.EapMeth, "", "", ""
		if f.Type == 0 {
			code = eapCode[f.EapCode]
			if f.Identity != "" {
				notes = "identity=" + f.Identity
			}
		}
		if f.Type == 3 {
			kv, rc = strconv.Itoa(f.KeyVer), strconv.FormatUint(f.ReplayCtr, 10)
			if f.HandshakeM > 0 {
				what = "M" + strconv.Itoa(f.HandshakeM)
			} else {
				what = "group key"
			}
			if f.PMKID != nil {
				notes = "PMKID " + hex.EncodeToString(f.PMKID)[:12] + "…"
			}
		}
		ft.Rows = append(ft.Rows, []string{strconv.Itoa(f.Index), f.Src, f.Dst, f.TypeStr, code, what, kv, rc, notes})
	}
	r.addTable(ft)
	sessions := buildSessions(frames)
	r.stat("sessions", strconv.Itoa(len(sessions)))
	st := Table{Title: "Sessions (authenticator ↔ supplicant)", Headers: []string{"AP / Authenticator", "SSID", "AKM", "Client", "M1", "M2", "M3", "M4", "PMKID", "Crackable pairs", "EAP ok/fail"}}
	for _, s := range sessions {
		n := nets[s.AP]
		st.Rows = append(st.Rows, []string{s.AP, n.SSID, strings.Join(n.AKMs, "+"), s.STA, strconv.Itoa(s.M[1]), strconv.Itoa(s.M[2]), strconv.Itoa(s.M[3]), strconv.Itoa(s.M[4]),
			yn(s.PMKID != nil), strings.Join(s.Pairs, ", "), fmt.Sprintf("%d/%d", s.EapOK, s.EapFail)})
	}
	r.addTable(st)
	eapolFindings(r, frames, sessions, nets)
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func eapolFindings(r *Report, frames []EapolFrame, sessions []*session, nets map[string]bssInfo) {
	// weak EAP methods offered or accepted
	methods := map[int][]string{}
	for _, s := range sessions {
		for t := range s.Methods {
			methods[t] = append(methods[t], s.STA)
		}
	}
	var mk []int
	for t := range methods {
		mk = append(mk, t)
	}
	sort.Ints(mk)
	mt := Table{Title: "EAP Methods Observed", Headers: []string{"Type", "Method", "Strength", "Note"}}
	for _, t := range mk {
		m, ok := eapTypes[t]
		if !ok {
			m = eapMethod{Name: fmt.Sprintf("EAP-Type-%d", t)}
		}
		mt.Rows = append(mt.Rows, []string{strconv.Itoa(t), m.Name, map[bool]string{true: "WEAK", false: "ok"}[m.Weak], m.Note})
		if ok && m.Weak {
			sev := SevHigh
			if t == 17 || t == 4 {
				sev = SevCrit
			}
			r.add(Finding{ID: fmt.Sprintf("EAPOL-WEAK-EAP-%d", t), Title: "Weak EAP method: " + m.Name, Sev: sev,
				Desc: fmt.Sprintf("%s was negotiated by %d client(s). %s", m.Name, len(uniqueStrs(methods[t])), m.Note),
				Loc:  strings.Join(uniqueStrs(methods[t]), ", "), Mitre: []string{"T1557", "T1110"},
				Rec: "Migrate to EAP-TLS (mutual certificates) or PEAP/TTLS with strict server-certificate validation."})
		}
	}
	if len(mt.Rows) > 0 {
		r.addTable(mt)
	}
	// cleartext identities
	var ids []string
	for _, f := range frames {
		if f.Identity != "" && !strings.HasPrefix(strings.ToLower(f.Identity), "anonymous") {
			ids = append(ids, f.Identity)
		}
	}
	if ids = uniqueStrs(ids); len(ids) > 0 {
		r.add(Finding{ID: "EAPOL-IDENTITY", Title: "Real usernames sent as cleartext EAP-Identity", Sev: SevLow,
			Desc:  fmt.Sprintf("%d identity(ies) disclosed in the outer EAP-Identity response: %s", len(ids), strings.Join(firstN(ids, 8), ", ")),
			Mitre: []string{"T1040", "T1589.001"}, Rec: "Use an anonymous outer identity (anonymous@realm) on every supplicant profile."})
	}
	// per session: offline-crackable material, PMKID, failures, TKIP
	var crack, pmkid, fails []string
	var notPSK []string
	for _, s := range sessions {
		cls := akmClass(nets[s.AP].AKMs)
		label := s.AP + " ↔ " + s.STA
		if ss := nets[s.AP].SSID; ss != "" {
			label = fmt.Sprintf("%q %s", ss, label)
		}
		psk := cls == "psk" || cls == "psk+sae" || cls == ""
		if len(s.Pairs) > 0 {
			if psk {
				note := ""
				if s.M[3] == 0 {
					note = " (unconfirmed: no M3 — the AP may have rejected this client's key)"
				}
				crack = append(crack, label+": "+strings.Join(s.Pairs, ", ")+note)
			} else {
				notPSK = append(notPSK, label+" ("+cls+")")
			}
		}
		if s.PMKID != nil && psk {
			pmkid = append(pmkid, label)
		}
		if s.M[1] >= 3 && s.M[3] == 0 && s.M[2] > 0 {
			fails = append(fails, fmt.Sprintf("%s: %d×M1, %d×M2, no M3", label, s.M[1], s.M[2]))
		}
		if s.EapFail >= 3 {
			fails = append(fails, fmt.Sprintf("%s: %d EAP-Failure", label, s.EapFail))
		}
	}
	unknownAKM := ""
	if len(nets) == 0 {
		unknownAKM = " No beacons were captured, so the network type is unknown — this applies if it uses WPA/WPA2-PSK."
	}
	if len(crack) > 0 {
		r.add(Finding{ID: "EAPOL-HANDSHAKE", Title: "Offline-crackable 4-way handshake captured", Sev: SevHigh,
			Desc: "Matching handshake messages from the same session are present — enough to test PSK guesses offline with no further contact with the network." + unknownAKM,
			Loc:  strings.Join(firstN(crack, 6), "; "), Mitre: []string{"T1557", "T1110.002"},
			Rec: "Use a long random passphrase (≥20 chars) or move to WPA3-SAE / 802.1X; treat this capture as sensitive."})
	}
	if len(pmkid) > 0 {
		r.add(Finding{ID: "EAPOL-PMKID", Title: "PMKID exposed in message 1 (clientless attack)", Sev: SevHigh,
			Desc: "The AP includes a PMKID in M1. An attacker only needs to associate once — no client and no deauthentication — to obtain material for an offline PSK attack." + unknownAKM,
			Loc:  strings.Join(firstN(pmkid, 6), "; "), Mitre: []string{"T1110.002"},
			Rec: "Disable PMKID caching for PSK networks (vendor option) or move to WPA3-SAE; use a long random passphrase."})
	}
	if len(notPSK) > 0 {
		r.add(Finding{ID: "EAPOL-HANDSHAKE-SAFE", Title: "Handshakes on non-PSK networks", Sev: SevInfo,
			Desc: "Complete handshakes were captured on SAE/802.1X/OWE networks; their keys do not derive from a guessable passphrase, so they are not offline-crackable.",
			Loc:  strings.Join(firstN(notPSK, 6), "; ")})
	}
	if len(fails) > 0 {
		r.add(Finding{ID: "EAPOL-FAILED-AUTH", Title: "Repeated failed authentications", Sev: SevMed,
			Desc: "Handshakes repeatedly stop after M2 (the AP rejected the MIC — wrong passphrase) or EAP keeps failing: consistent with online password guessing or a misconfigured client.",
			Loc:  strings.Join(firstN(fails, 6), "; "), Mitre: []string{"T1110"},
			Rec: "Check AP logs for the client MAC; rate-limit or block it; confirm the client's stored credentials."})
	}
	for _, s := range sessions {
		if s.M3Resend > 0 {
			r.add(Finding{ID: "EAPOL-M3-RETRANSMIT", Title: "Message 3 retransmitted", Sev: SevInfo,
				Desc:  fmt.Sprintf("M3 was retransmitted %d time(s) between %s and %s. Unpatched clients reinstall the PTK on a repeated M3 (KRACK, CVE-2017-13077); ensure clients are patched.", s.M3Resend, s.AP, s.STA),
				Mitre: []string{"T1557"}})
			break
		}
	}
	vers := map[int]bool{}
	for _, f := range frames {
		if f.Type == 3 {
			vers[f.KeyVer] = true
		}
	}
	if vers[1] {
		r.add(Finding{ID: "EAPOL-TKIP", Title: "WPA/TKIP key descriptor", Sev: SevMed,
			Desc:  "EAPOL-Key descriptor version 1 (HMAC-MD5 / RC4) means WPA-TKIP, deprecated and vulnerable (Michael MIC, Beck-Tews).",
			Mitre: []string{"T1557"}, Rec: "Disable TKIP; require CCMP (AES)."})
	}
	if vers[0] {
		r.add(Finding{ID: "EAPOL-AKM-DEFINED", Title: "AKM-defined key descriptor (WPA3 / OWE / FT-SAE)", Sev: SevInfo,
			Desc: "Descriptor version 0 is used by modern AKMs such as SAE and OWE."})
	}
}

func uniqueStrs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func firstN(in []string, n int) []string {
	if len(in) > n {
		return append(append([]string{}, in[:n]...), fmt.Sprintf("… %d more", len(in)-n))
	}
	return in
}

func analyze(src string, demo bool, filter string) *Report {
	r := newReport(src)
	var frames []CapFrame
	var err error
	if demo {
		r.Source = "[synthetic capture: PSK network with PMKID, failed client, wired 802.1X with LEAP]"
		frames, _, err = decodeCapture(demoCapture())
	} else {
		frames, _, err = loadCapture(src)
	}
	if err != nil {
		r.note("load error: " + err.Error())
		r.grade()
		return r
	}
	analyzeFrames(r, frames, filter)
	r.grade()
	return r
}

// ---- synthetic demo capture (built as real bytes, parsed by the real pipeline) ----

func eapolKeyPDU(info uint16, replay uint64, nonce byte, keyData []byte) []byte {
	body := make([]byte, 95)
	body[0] = 2
	binary.BigEndian.PutUint16(body[1:], info)
	binary.BigEndian.PutUint16(body[3:], 16)
	binary.BigEndian.PutUint64(body[5:], replay)
	if nonce != 0 {
		for i := 13; i < 45; i++ {
			body[i] = nonce + byte(i)
		}
	}
	if info&0x0100 != 0 {
		for i := 77; i < 93; i++ {
			body[i] = 0x5a
		}
	}
	binary.BigEndian.PutUint16(body[93:], uint16(len(keyData)))
	body = append(body, keyData...)
	return append([]byte{2, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

func dot11Data(fromAP bool, ap, sta []byte, qos bool, pdu []byte) []byte {
	fc := []byte{0x08, 0x01} // data, to DS
	a1, a2, a3 := ap, sta, ap
	if fromAP {
		fc[1], a1, a2, a3 = 0x02, sta, ap, ap
	}
	if qos {
		fc[0] = 0x88
	}
	h := append(append(append(append(fc, 0, 0), a1...), a2...), a3...)
	h = append(h, 0, 0)
	if qos {
		h = append(h, 0, 0)
	}
	h = append(h, 0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e)
	return append(h, pdu...)
}

func demoCapture() []byte {
	ap := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	sta := []byte{0x3c, 0x07, 0x54, 0x01, 0x02, 0x03}
	bad := []byte{0x9a, 0xbb, 0xcc, 0x00, 0x00, 0x07}
	rt := []byte{0, 0, 8, 0, 0, 0, 0, 0}
	var pk [][]byte
	// beacon: SSID OwlLab-PSK, RSN with PSK AKM
	bcn := []byte{0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	bcn = append(append(append(bcn, ap...), ap...), 0, 0)
	bcn = append(bcn, make([]byte, 8)...)
	bcn = append(bcn, 0x64, 0, 0x11, 0x04)
	bcn = append(bcn, 0, 10)
	bcn = append(bcn, "OwlLab-PSK"...)
	bcn = append(bcn, 48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0)
	pk = append(pk, append(rt, bcn...))
	// good client: M1 (with PMKID KDE), M2 (RSN IE), M3, M3 resend, M4
	pmkidKDE := append([]byte{0xdd, 20, 0x00, 0x0f, 0xac, 0x04}, []byte("PMKIDPMKIDPMKID!")...)
	rsnIE := []byte{48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0}
	pk = append(pk, append(rt, dot11Data(true, ap, sta, false, eapolKeyPDU(0x008a, 1, 0x10, pmkidKDE))...))
	pk = append(pk, append(rt, dot11Data(false, ap, sta, true, eapolKeyPDU(0x010a, 1, 0x40, rsnIE))...))
	m3 := eapolKeyPDU(0x13ca, 2, 0x10, make([]byte, 56))
	pk = append(pk, append(rt, dot11Data(true, ap, sta, false, m3)...))
	pk = append(pk, append(rt, dot11Data(true, ap, sta, false, eapolKeyPDU(0x13ca, 3, 0x10, make([]byte, 56)))...))
	pk = append(pk, append(rt, dot11Data(false, ap, sta, true, eapolKeyPDU(0x030a, 3, 0, nil))...))
	// second client keeps failing: M1/M2 ×4, never an M3
	for i := uint64(0); i < 4; i++ {
		pk = append(pk, append(rt, dot11Data(true, ap, bad, false, eapolKeyPDU(0x008a, 10+i, 0x20, nil))...))
		pk = append(pk, append(rt, dot11Data(false, ap, bad, false, eapolKeyPDU(0x010a, 10+i, 0x60, rsnIE))...))
	}
	// an encrypted data frame and a non-EAPOL frame that must be ignored
	pk = append(pk, append(rt, append([]byte{0x08, 0x42}, make([]byte, 40)...)...))
	pk = append(pk, append(rt, dot11Data(false, ap, sta, false, []byte{0x45, 0, 0, 20})...))
	// wired 802.1X exchange on a switch port (Ethernet link type)
	sw := []byte{0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x01}
	pc := []byte{0x00, 0x50, 0x56, 0x12, 0x34, 0x56}
	eth := func(src, dst []byte, pdu []byte) []byte {
		return append(append(append(append([]byte{}, dst...), src...), 0x88, 0x8e), pdu...)
	}
	eap := func(code, id, typ byte, data []byte) []byte {
		l := 5 + len(data)
		p := append([]byte{code, id, byte(l >> 8), byte(l), typ}, data...)
		return append([]byte{2, 0, byte(l >> 8), byte(l)}, p...)
	}
	var wired [][]byte
	wired = append(wired, eth(pc, []byte{0x01, 0x80, 0xc2, 0, 0, 3}, []byte{2, 1, 0, 0}))
	wired = append(wired, eth(sw, pc, eap(1, 1, 1, nil)))
	wired = append(wired, eth(pc, sw, eap(2, 1, 1, []byte("alice@corp.example"))))
	wired = append(wired, eth(sw, pc, eap(1, 2, 17, []byte{1, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})))
	wired = append(wired, eth(pc, sw, eap(2, 2, 17, make([]byte, 27))))
	wired = append(wired, eth(sw, pc, []byte{2, 0, 0, 4, 3, 2, 0, 4}))
	return mergeCaptures(capWriter(127, pk, 1730275200), capWriter(1, wired, 1730275300))
}

// capWriter builds a classic pcap with one link type.
func capWriter(link uint32, pkts [][]byte, ts uint32) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], link)
	for i, p := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec, ts+uint32(i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(p)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(p)))
		h = append(append(h, rec...), p...)
	}
	return h
}

// mergeCaptures combines two single-link pcaps into a pcapng with one
// interface per input, so a single demo exercises 802.11 and Ethernet.
func mergeCaptures(caps ...[]byte) []byte {
	le := binary.LittleEndian
	block := func(typ uint32, body []byte) []byte {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		n := uint32(12 + len(body))
		b := make([]byte, 8)
		le.PutUint32(b, typ)
		le.PutUint32(b[4:], n)
		b = append(b, body...)
		t := make([]byte, 4)
		le.PutUint32(t, n)
		return append(b, t...)
	}
	shb := make([]byte, 16)
	le.PutUint32(shb, 0x1a2b3c4d)
	le.PutUint16(shb[4:], 1)
	for i := 8; i < 16; i++ {
		shb[i] = 0xff
	}
	out := block(0x0a0d0d0a, shb)
	for i, c := range caps {
		fr, link, err := parsePcap(c)
		if err != nil {
			continue
		}
		idb := make([]byte, 8)
		le.PutUint16(idb, uint16(link))
		le.PutUint32(idb[4:], 65535)
		out = append(out, block(1, idb)...)
		for _, f := range fr {
			epb := make([]byte, 20)
			le.PutUint32(epb, uint32(i))
			us := uint64(f.TsSec)*1e6 + uint64(f.TsUsec)
			le.PutUint32(epb[4:], uint32(us>>32))
			le.PutUint32(epb[8:], uint32(us))
			le.PutUint32(epb[12:], uint32(len(f.Data)))
			le.PutUint32(epb[16:], uint32(len(f.Data)))
			out = append(out, block(6, append(epb, f.Data...))...)
		}
	}
	return out
}

// ---------- self-test ----------

func runSelfTest() bool {
	banner()
	pass, fail := 0, 0
	check := func(n string, ok bool, got string) {
		if ok {
			okMsg(n)
			pass++
		} else {
			errMsg(n + "  →  " + got)
			fail++
		}
	}
	frames, _, err := decodeCapture(demoCapture())
	check("pcapng with two link types decoded", err == nil && len(frames) == 22, fmt.Sprint(err, len(frames)))
	links := map[uint32]int{}
	for _, f := range frames {
		links[f.LinkType]++
	}
	check("per-interface link types kept (radiotap + Ethernet)", links[127] == 16 && links[1] == 6, fmt.Sprint(links))
	pk := extractEapol(frames)
	check("only real EAPOL extracted (beacon / encrypted / IP ignored)", len(pk) == 19, strconv.Itoa(len(pk)))
	var fr []EapolFrame
	for _, p := range pk {
		fr = append(fr, parseEapol(p))
	}
	ms := ""
	for _, f := range fr[:5] {
		ms += strconv.Itoa(f.HandshakeM)
	}
	check("M1 M2 M3 M3 M4 classified (QoS header, zero-nonce M4)", ms == "12334", ms)
	check("PMKID KDE extracted from M1", fr[0].PMKID != nil && string(fr[0].PMKID) == "PMKIDPMKIDPMKID!", "")
	check("EAP identity extracted", func() bool {
		for _, f := range fr {
			if f.Identity == "alice@corp.example" {
				return true
			}
		}
		return false
	}(), "")
	nets := beaconAKMs(frames)
	check("beacon RSN → PSK network", akmClass(nets["02:11:22:33:44:55"].AKMs) == "psk" && nets["02:11:22:33:44:55"].SSID == "OwlLab-PSK", fmt.Sprint(nets))
	r := analyze("", true, "")
	ids := map[string]string{}
	for _, f := range r.Findings {
		ids[f.ID] = f.Sev
	}
	check("findings: handshake, PMKID, failed auth, LEAP, identity, M3 resend", ids["EAPOL-HANDSHAKE"] != "" && ids["EAPOL-PMKID"] != "" && ids["EAPOL-FAILED-AUTH"] != "" && ids["EAPOL-WEAK-EAP-17"] == SevCrit && ids["EAPOL-IDENTITY"] != "" && ids["EAPOL-M3-RETRANSMIT"] != "", fmt.Sprint(ids))
	// a WPA3-SAE network: handshake is not offline-crackable
	sess := buildSessions(fr[:5])
	cls := akmClass([]string{"SAE (WPA3)"})
	check("SAE network classified as not PSK", cls == "sae" && len(sess) == 1 && len(sess[0].Pairs) == 2, fmt.Sprint(cls, sess[0].Pairs))
	// random bytes must never be accepted as EAPOL
	junk := []CapFrame{{Data: []byte{0x45, 0x00, 0x00, 0x1c, 1, 2, 3, 4, 5, 6, 7, 8}, LinkType: LinkHexEapol}, {Data: []byte("hello world, not eapol"), LinkType: LinkHexEapol},
		{Data: []byte{2, 3, 0, 0, 9, 9, 9, 9}, LinkType: LinkRaw}} // raw-IP link type never carries EAPOL
	check("non-EAPOL raw input rejected", len(extractEapol(junk)) == 0, "")
	// nanosecond pcap magic
	ns := capWriter(1, nil, 0)
	binary.LittleEndian.PutUint32(ns, 0xa1b23c4d)
	_, _, err = decodeCapture(ns)
	check("nanosecond pcap accepted", err == nil, fmt.Sprint(err))
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
	}
	return fail == 0
}

// ---------- interactive handlers ----------

func handleEapTypes() {
	sectionHead("EAP Method Registry (subset)")
	var keys []int
	for k := range eapTypes {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	rows := [][]string{}
	for _, k := range keys {
		m := eapTypes[k]
		s := "ok"
		if m.Weak {
			s = "WEAK"
		}
		rows = append(rows, []string{strconv.Itoa(k), m.Name, s})
	}
	table([]string{"Type", "Method", "Strength"}, rows)
}
func handleEapolTypes() {
	sectionHead("EAPOL Packet Types")
	var keys []int
	for k := range eapolType {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{strconv.Itoa(k), eapolType[k]})
	}
	table([]string{"Type", "Name"}, rows)
}

var menuDef = []menuEntry{
	{"Analyze EAPOL capture", "pcap/pcapng/hex: sessions, PMKID, EAP", handleRunFile},
	{"Run synthetic demo", "PSK + PMKID, failed client, wired LEAP", handleRunDemo},
	{"EAP method registry", "Method types and their strength", handleEapTypes},
	{"EAPOL packet types", "802.1X packet-type reference", handleEapolTypes},
	{"Export last report", "txt / md / json / csv / sarif", handleExport},
	{"Self-test", "Parser and detector checks", func() { runSelfTest() }},
}

var howtoWarning = "OEAPOL is for AUTHORIZED 802.1X/WPA analysis only. Only analyze captures from networks you own or are permitted to test. Capturing authentication traffic of others may be illegal. This tool is OFFLINE and sends nothing."

var howtoSteps = []string{
	"Capture EAPOL frames (ethertype 0x888E) on an authorized engagement, e.g. with tcpdump/airodump.",
	"Run OEAPOL with no arguments for the TUI, or 'OEAPOL --pcap auth.pcap' for CLI mode.",
	"Choose 'Analyze EAPOL capture', or 'Run synthetic 802.1X demo' to see a full flow.",
	"Review the EAPOL/EAP Frames, EAP Methods and 4-Way Handshake tables.",
	"Read FINDINGS: crackable handshake pairs, exposed PMKIDs, failed-auth bursts, weak EAP methods, leaked identities, TKIP.",
	"Export with 'Export report' or '--format sarif --output eapol.sarif'.",
}
var howtoNav = []string{
	"[01] Analyze a capture  — sessions, M1–M4, PMKID, EAP methods, identities",
	"[02] Demo  — PSK network with PMKID, a failing client, wired 802.1X with LEAP",
	"[03] EAP registry  — method type reference with strength",
	"[04] EAPOL types  — packet-type reference",
	"[05] Export last report / [06] Self-test / [07] HOW TO USE / [0] Exit",
}
var howtoReq = []string{
	"A pcap/pcapng or hex dump containing EAPOL frames.",
	"No privileges required for analysis — it is offline.",
	"Link types: 802.11, radiotap, PPI, Ethernet (+VLAN), Linux SLL; hex input may be raw EAPOL or LLC/Ethernet-wrapped.",
	"Beacons in the capture tell PSK from SAE/802.1X networks, so non-crackable handshakes are not flagged.",
}
var howtoNotes = []string{
	"EAPOL header: version(1) type(1) length(2). Type 0 is EAP-Packet, type 3 is EAPOL-Key (the 4-way handshake).",
	"EAP methods: EAP-MD5 and LEAP are broken; MSCHAPv2 is crackable without a validated tunnel; EAP-TLS is strong.",
	"The 4-way handshake is classified by Key Information bits plus the nonce (M4 carries a zero nonce).",
	"Crackable pairs need the same session: M1+M2 share a replay counter, M3 = M2 + 1. A PMKID in M1 alone is enough.",
	"Capturing M1+M2 is enough for an offline PSK dictionary attack (OHandshake exports it for hashcat -m 22000).",
	"EAPOL-Key version 1 = WPA/TKIP (deprecated); version 2 = WPA2/CCMP; version 3 = AES-128-CMAC.",
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OEAPOL analyses 802.1X / EAPOL authentication traffic from capture files. For Wi-Fi WPA/WPA2-PSK it rebuilds every 4-way handshake (M1-M4), pairs messages from the same session, and reports which handshakes and PMKIDs are complete enough to be cracked offline. For enterprise / wired 802.1X it lists the EAP methods used, flags weak ones (EAP-MD5, LEAP, MSCHAPv2 without a validated tunnel) and shows identities leaked in clear text. It also flags failed-authentication bursts and old WPA/TKIP.",
	"Beacons in the capture tell PSK networks from SAE (WPA3) and 802.1X networks, so handshakes that cannot be cracked are not flagged.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. Start with [01] and give it a capture, or try [02] to see a full example. [H] opens this help, [0] or q quits.",
	"Accepted input: pcap / pcapng (802.11, radiotap, PPI, Ethernet + VLAN, Linux SLL) or a text file with EAPOL frames as hex.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Analyze EAPOL capture: enter the capture path. Shows the EAPOL/EAP frame table, the EAP methods, the 4-way handshake table per AP/client, and findings with a grade."},
	{"02", "Run synthetic demo: a PSK network with a PMKID, a client that keeps failing, and wired 802.1X using LEAP."},
	{"03", "EAP method registry: EAP type numbers (PEAP, TTLS, TLS, MD5, LEAP ...) and how strong each one is."},
	{"04", "EAPOL packet types: reference of the 802.1X packet types (EAP-Packet, Start, Logoff, Key ...)."},
	{"05", "Export last report: choose txt, md, json, csv or sarif and an output file (blank = print to screen). If nothing was analysed yet, you are asked for an input file first (blank = demo)."},
	{"06", "Self-test: parser and detector checks."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "M1+M2 of the same session, or a PMKID in M1 alone, is enough for an offline PSK dictionary test. Use OHandshake to export it for hashcat -m 22000."},
	{"*", "--target MAC limits the report to one AP or client (a partial MAC is fine, e.g. aa:bb:cc)."},
	{"*", "Record in monitor mode on the AP's channel, then reconnect a client you own so the handshake is captured."},
	{"*", "The legal notes and protocol details are on page 3."},
}

func owlHelpCLI() {
	usage()
	pause()
	showHowto()
}
