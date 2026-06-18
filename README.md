# esp32.network — Netzwerk-Scanner für ESP32

![Version](https://img.shields.io/badge/version-1.6.6-blue)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C.svg?logo=paypal)](https://www.paypal.com/donate/?business=martin%40bchmnn.de&currency_code=EUR)

> **Netzwerk-Scanner für ESP32** — Alle Teilnehmer im Heimnetz scannen, überwachen und benennen.

---

## Features

- 🌐 **Multi-Port-Scan** — prüft Ports 80, 8080, 8093, 443, 22, 23, 21 pro IP
- ⏱️ **Auto-Scan** — konfigurierbares Intervall
- 📊 **Live-Fortschritt** per SSE während des Scans
- 🔍 **Ping** pro Gerät — 3x TCP, Min/Avg/Max/Loss
- 🔌 **Port-Scanner** pro Gerät — 20 Standard-Ports, klickbare Links
- 🏷️ **Label + Notiz** pro Gerät (persistent in NVS)
- 🖥️ **Gerät-Typ-Icon** — Router/PC/ESP32/Phone/Printer/TV/NAS/Kamera/Switch
- ⏳ **Uptime-Tracking** — Online seit / Offline seit
- 🚀 **OTA-Update** — Browser Drag&Drop + ESP-Hub Push
- 🤝 **ioBroker-Integration** — Heartbeat mit `devices` und `online` IO-Werten
- 🔄 **Hub-Name Sync** — Umbenennung im ESP-Hub wird übernommen

---

## Warum Multi-Port-Scan?

Geräte werden nur gefunden wenn sie auf **mindestens einem Port** antworten:

| Gerät | Port | Vorher | Jetzt |
|-------|------|--------|-------|
| HTTP-Geräte | 80 | ✅ | ✅ |
| ioBroker/ESP-Hub | 8093 | ❌ | ✅ |
| Andere Web-UIs | 8080 | ❌ | ✅ |
| HTTPS | 443 | ❌ | ✅ |
| SSH/Linux | 22 | ❌ | ✅ |
| Telnet | 23 | ❌ | ✅ |

---

## Quickstart

1. Sketch flashen
2. Mit WLAN-Hotspot **"ESP-Net-Setup"** verbinden
3. WLAN + ESP-Hub IP eingeben
4. `http://<ESP-IP>/` öffnen → Scan starten

---

## Einstellungen

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| Scan-Intervall | 5 min | 0 = nur manuell |
| Ping-Timeout | 300 ms | pro Port, 100–2000ms |
| Subnetz-Basis | auto | z.B. `192.168.178` |

---

## Lizenz

GNU General Public License v3.0 — © MPunktBPunkt

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C.svg?logo=paypal)](https://www.paypal.com/donate/?business=martin%40bchmnn.de&currency_code=EUR)

---

## Changelog

### 1.2.0
- Fix: Multi-Port-Scan (80, 8080, 8093, 443, 22, 23, 21) — findet deutlich mehr Geräte
- Fix: Hostname "-" statt `&#x2013;` HTML-Entity
- Neu: Hub-Name Sync aus Heartbeat-Response
- Neu: Subnetz wird automatisch aus WLAN-IP ermittelt

### 1.1.0
- Neu: Ping pro Gerät (3x TCP, Min/Avg/Max/Loss)
- Neu: Port-Scanner pro Gerät (20 Ports)
- Neu: Gerät-Typ-Icons, Notizen, Uptime-Tracking

### 1.0.0
- Erstveröffentlichung
