# 🦉 OEAPOL

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Wireless%20/%20RF-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OEAPOL** — EAPOL/802.1X Analyzer ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OEAPOL — EAPOL/802.1X Analyzer. OWL Security Tools · Batch 3 (Wireless) This tool performs OFFLINE analysis of wireless protocol artifacts (pcap, hex, CSV, IQ, NMEA, LDIF-style captures). It never touches a live radio.

---

## ✨ Features

- Parse and analyze EAPOL / 802.1X exchanges from captures
- Identify handshake stages, identity leaks and failure causes
- Support offline pcap workflows for wireless lab review
- Highlight weak or incomplete authentication sequences
- Interactive TUI and CLI reporting
- Export analysis to TXT/Markdown/JSON/CSV/SARIF

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OEAPOL OEAPOL.go
./OEAPOL --help
./OEAPOL --input auth.pcap
./OEAPOL --input auth.pcap --format md
./OEAPOL --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
