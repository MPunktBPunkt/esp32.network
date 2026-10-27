# esp32.network

![Version](https://img.shields.io/badge/version-1.7.0-blue)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C.svg?logo=paypal)](https://www.paypal.com/donate/?business=martin%40bchmnn.de&currency_code=EUR)

> **Netzwerk-Scanner für ESP32** — Geräte im Heimnetz finden, überwachen und benennen. Integriert in ioBroker über [iobroker.esp-hub](https://github.com/MPunktBPunkt/iobroker.esp-hub). Shared Core aus [ESP32.esp-hub](https://github.com/MPunktBPunkt/ESP32.esp-hub) **1.10.5**.

---

## Überblick

`esp32.network` scannt dein lokales Subnetz, erkennt aktive Geräte über mehrere TCP-Ports und hält ein persistentes Inventar mit Labels, Notizen und Online-Status. Optional werden stille Geräte über die **FritzBox TR-064-Schnittstelle** angereichert. Alles steuerbar über eine moderne Web-Oberfläche — und sichtbar im ESP-Hub-Dashboard.

**1.7.0:** `HardwareInfo`/`CpuLoad` aus dem Base-Core; Web-UI als `web/*.html` → gzip-PROGMEM (wie Base/Ergo/rfmonitor).

---

## Features

- **Multi-Port-Scan** — Ports 80, 8080, 8093, 443, 22, 23, 21 und mehr
- **Auto-Scan** — konfigurierbares Intervall oder manuell
- **Live-Fortschritt** — SSE während des Scans
- **Ping & Port-Scanner** — pro Gerät mit klickbaren Links
- **Geräte-Inventar** — Label, Notiz, Typ-Icon, Uptime-Tracking (NVS)
- **FritzBox-Integration** — TR-064 Hostliste mergen (HTTPS Port 49443)
- **ESP-Hub** — Heartbeat mit `devices` und `online` als IO-Werte, Name-Sync, OTA-Push
- **Browser-OTA** — Firmware per Drag & Drop
- **Hardware/CPU** — `hwSummary`, Flash, CPU-Last in Status/Heartbeat

---

## Voraussetzungen

| Typ | Details |
|-----|---------|
| **Board** | ESP32 (getestet: Wemos D1 Mini ESP32) / ESP32-S3 |
| **WiFiManager** | tablatronix / tzapu |
| **ArduinoJson** | bblanchon v6 oder v7 |
| **ioBroker** | [iobroker.esp-hub](https://github.com/MPunktBPunkt/iobroker.esp-hub) auf Port **8093** |
| **Python** | für UI-Pack: `python3 tools/pack_ui.py` vor dem Build nach HTML-Änderungen |

---

## Quickstart

1. Gesamten Ordner `esp32.network/` mit Arduino IDE / `arduino-cli` bauen (nicht nur die `.ino`)
2. Optional anpassen: `DEVICE_NAME`, `HUB_HOST`, `HUB_PORT`
3. Auf ESP32 flashen
4. Mit WLAN-Hotspot **`ESP-Net-Setup`** verbinden → WLAN + Hub-IP eingeben
5. Web-UI: `http://<ESP-IP>/` → Scan starten
6. Gerät erscheint im ESP-Hub unter `http://<ioBroker-IP>:8093`

> **WLAN zurücksetzen:** BOOT-Taste (GPIO0) beim Einschalten 3 Sekunden halten

### Web-UI bearbeiten

```
web/index.html + web/ota.html  →  python3 tools/pack_ui.py  →  src/web/UiPagesGz.h
```

Build-Hinweis: `arduino-cli compile … --build-property 'compiler.cpp.extra_flags=-Isrc'`.

---

## Vorkompilierte Firmware

Schema: `{name}.{version}.{family}.bin`

| Datei | Board |
|-------|-------|
| `network.1.7.0.esp32.bin` | ESP32 / D1 Mini |
| `network.1.7.0.esp32s3.bin` | ESP32-S3 |

---

## Konfiguration

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| Scan-Intervall | 30 s | 0 = nur manuell |
| Ping-Timeout | 300 ms | pro Port (100–2000 ms) |
| Subnetz-Basis | auto | z. B. `192.168.178` |
| FritzBox Host/User/Pass | leer | optional, TR-064 Pull |
| Hub-Port | 8093 | ESP-Hub Adapter |

---

## ioBroker-Integration (ESP-Hub)

Der Scanner sendet regelmäßig einen Heartbeat an `POST /api/register`:

```
esp-hub.0.devices.<MAC>/
├── name, ip, version, rssi, uptime, freeHeap, hwSummary, module, cpu
└── ios/
    ├── devices   ← Anzahl erkannter Geräte
    └── online    ← aktuell online
```

Dashboard: `http://<ioBroker-IP>:8093`

---

## Lizenz

GNU General Public License v3.0 © MPunktBPunkt — siehe [LICENSE](LICENSE)
