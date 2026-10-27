#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <MD5Builder.h>
#include <Update.h>
#include <Preferences.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <WiFiManager.h>
#include <ArduinoJson.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/etharp.h>
#include <fcntl.h>
#include <esp_system.h>
#include "esphub/HardwareInfo.h"
#include "esphub/CpuLoad.h"
#include "web/UiPages.h"

// ================================================================
//  KONFIGURATION
// ================================================================
// v1.7.0: esp-hub-base Shared-Core Stufe A/B (Validierung)
//  - HardwareInfo + CpuLoad aus ESP32.esp-hub 1.10.5 (src/esphub/)
//  - Web-UI: web/index.html + web/ota.html → gzip-PROGMEM (pack_ui.py)
//  - /api/status + Heartbeat: version, hwSummary, cpu*, flash*, module
//  - Hub-Rename (reply.name) unveraendert
// v1.6.6: Typheuristik erweitert (Review 4)
//  - Neue Hostname-Muster fuer Geraete die mit FritzBox-Namen
//    jetzt oft gut benannt sind, aber noch als "Unknown" landeten:
//    iphone/ipad->Phone/Tablet, watch->Phone(Wearable), tv/
//    samsungtv/philipstv->TV, laptop/notebook->PC, robi->Vacuum
//  - Reihenfolge bewusst vor Vacuum-Block: "xiaomirobi" muss
//    "robi" treffen auch wenn "vacuum"/"roborock" nicht enthalten
// v1.6.5: Fix IP-CHG-Eventtext abgeschnitten (Review 2)
//  - "%.13s->%.13s" kuerzte jede IPv4-Adresse (max 15 Zeichen)
//    auf 13 Zeichen -> "192.168.178.1->192.168.178." statt
//    "192.168.178.1->192.168.178.105"
//  - NetEvent.info auf 36 Bytes vergroessert (15+2+15+1=33,
//    aufgerundet) und beide IP-CHG-Stellen (mergeByMac,
//    fritzboxPoll) auf "%s->%s" ohne Truncation umgestellt
// v1.6.4: Fix FritzBox-Karte erschien auf allen Tabs
//  - v1.6.3 hat beim Entfernen des doppelten Speichern-Buttons
//    ein zu frueh schliessendes </div> hinterlassen: die
//    FritzBox-Karte + Speichern-Button lagen dadurch AUSSERHALB
//    von .pane#pane-settings -> global sichtbar auf allen Tabs.
//    Jetzt korrekt innerhalb von pane-settings verschachtelt.
// v1.6.3: UI/Event-Fixes
//  - Doppelten "Speichern"-Button im Einstellungen-Tab entfernt
//    (war einmal nach Scan-Settings, einmal nach FritzBox-Karte)
//  - Events zeigen jetzt echte Uhrzeit statt "vor Xmin":
//    NTP-Sync via configTzTime() (deutsche Zeitzone inkl. DST),
//    addEvent() speichert time(nullptr) (Unix-Epoch) statt
//    millis()/1000; UI formatiert mit toLocaleString()
// v1.6.2: TR-064 auf HTTPS:49443 umgestellt
//  - FritzOS >= 7.50 deaktiviert den unverschlossenen Port 49000
//    standardmaessig (TR-064 nur noch via HTTPS mit selbstsigniertem
//    Zertifikat auf 49443). fritzboxRequest() nutzt jetzt
//    WiFiClientSecure + setInsecure() (Zertifikatspruefung aus,
//    da das FritzBox-Zertifikat selbstsigniert/lokal ist).
// v1.6.1: FritzBox-Diagnose (Review 9)
//  - fritzboxRequest() liefert jetzt HTTP-Code + ob 401/Digest-Retry
//    aufgetreten ist (lastHttpCode, lastAuthUsed, lastDigestRetry)
//  - fritzboxPoll() zaehlt itemsParsed/itemsMerged/itemsNew und
//    meldet den aufgeloesten HostListPath im Status
//  - /api/settings liefert diese Felder zur Fehlersuche mit aus
// v1.6.0: FritzBox-Integration (TR-064)
//  - Periodischer Pull der FritzBox-Geraeteliste
//    (X_AVM-DE_GetHostListPath, Hosts:1 Service)
//  - HTTP-Digest-Auth (MD5) fuer geschuetzte TR-064-Endpunkte
//  - Merge per MAC: bestaetigt/aktualisiert Geraete, legt neue
//    Inventar-Eintraege fuer router-bekannte stille Geraete an
//    (Echo, Handy, Tablet, Watch, Xiaomi Robi, ...)
//  - Konfigurierbar in den Einstellungen (Host/User/Pass/Intervall)
//  - ESP bleibt Reachability-/Enrichment-Layer, FritzBox liefert
//    die Inventar-/Praesenzwahrheit fuer "stille" Geraete
// v1.5.11 (Review-Batch):
//  - Presence nutzt jetzt 3 Stufen: lastSuccessPort -> openPortBits
//    (bekannte offene Ports aus Tiefenscan) -> FastScan-Fallback
//  - Optionale Consumer-/Media-Ports (8008/8009/8443/8888) als
//    letzte Stufe fuer bestaetigte Geraete (TV/Echo/Cast)
//  - tryGetMac() loggt Erfolg/Misserfolg auf Serial (Diagnose,
//    siehe Review: ARP-MAC ist best-effort und oft leer)
// v1.5.10: Heartbeat-Watchdog entfernt (analog io-control v1.2.1) -
//   Updates laufen weiter ueber den Hub, aber Hub-Erreichbarkeit darf
//   nie einen ESP.restart() ausloesen. Scanner soll auch ohne Hub
//   dauerhaft laufen.
// v1.5.9 Fixes (Review-Batch):
//  - NVS-Flush 15s versetzt zu Heartbeat (Reboot-Entkopplung)
//  - Reset-Reason wird beim Boot geloggt (esp_reset_reason)
//  - Portscan-Treffer setzt Geraet sofort online (Pflichtfix)
//  - FastScan 5->10 Ports fuer bessere Heimnetz-Abdeckung
//  - lastSuccessPort je Geraet, Presence prueft ihn zuerst
//  - Erweitertes Typmodell (Tablet/Speaker/SmartPlug/Vacuum/
//    Bridge/Repeater/Server), Amazon/Google/Nest -> Speaker
#define DEVICE_NAME           "Network Scanner"
#define FW_VERSION            "1.7.0"
#define HUB_HOST              "192.168.178.113"
#define HUB_PORT              8093
#define WIFI_AP_NAME          "ESP-Net-Setup"
#define WIFI_PORTAL_TIMEOUT_S 180
#define DEFAULT_INTERVAL_S    30
// Reset-Taste: GPIO 0 = BOOT-Taste auf ESP32.
// Auf 255 setzen um den Reset komplett zu deaktivieren
// (sinnvoll wenn BOOT-Taste versehentlich gedrueckt wird).
#define RESET_BUTTON_PIN      0
#define RESET_HOLD_SEC        3

// Watchdog: ESP neu starten wenn Heartbeat N Sekunden lang nicht
// erfolgreich war (0 = deaktiviert). Sichert gegen Haenger ab.
// Watchdog-Timeout in Sekunden (0 = deaktiviert).
// Setzt erst nach dem ERSTEN erfolgreichen Heartbeat ein.
// Auf 0 setzen wenn kein Hub vorhanden oder kein Auto-Reboot gewünscht.

// Feature-Flags: 0 = deaktiviert (sicher), 1 = aktiv
// ARP-MAC ist low-level lwIP und core-versionsabhaengig -> bei
// Build-Problemen zuerst auf 0 setzen und separat testen.
#define FEATURE_ARP_MAC      1   // MAC aus ARP-Cache nach TCP-Treffer
#define FEATURE_HTTP_NAME    1   // Hostname via HTTP-Title / Server-Header

#define MAX_DEVICES     64   // 64 Geraete x ~225 Bytes = ~14 KB DRAM

#define SCAN_START      1          // Fritzbox .1 einschliessen!
#define SCAN_END        254
#define MAX_EVENTS      150        // Ringpuffer Event-Log

// ================================================================
//  DATENSTRUKTUREN
// ================================================================
// Repraesentiert einen Netzwerkteilnehmer.
// Identitaet:  ip (aktuell), mac (stabiler Schluessel wenn ermittelt)
// Persistenz:  alle Felder ausser 'active' und 'changed' werden in NVS gespeichert.
// Automatisch: mac, vendor, hostname, dtype werden per Discovery befuellt.
// Manuell:     label, note, dtype koennen per UI ueberschrieben werden.
// Device: repraesentiert einen Netzwerkteilnehmer.
// Lebenszyklus: Candidate (probeSeen>0, confirmed=false) → Confirmed (lastSeen>0, confirmed=true)
// Felder confirmed/probeSeen/probeMiss/enrichQueued sind RAM-only (nicht persistiert).
// Nur confirmed=true mit lastSeen>0 werden in NVS gespeichert.
struct Device {
    // --- Identitaet (persistent) ---
    char     ip[16];        // Aktuelle IPv4-Adresse
    char     mac[18];       // MAC "AA:BB:CC:DD:EE:FF" oder "" wenn unbekannt
    char     vendor[24];    // OUI-Hersteller, z.B. "AVM", "Espressif"
    char     label[32];     // Manueller Name (UI-editierbar)
    char     note[64];      // Notiz (UI-editierbar)
    char     hostname[48];  // Via HTTP-Title oder Server-Header ermittelt
    uint8_t  dtype;         // 0=?,1=Router,2=PC,3=ESP,4=Phone,5=Drucker,6=TV,7=NAS,8=Kamera,9=Switch,
                            // 10=Tablet,11=Speaker,12=SmartPlug,13=Vacuum,14=Bridge,15=Repeater
    // --- Zeitstempel (persistent) ---
    unsigned long lastSeen;      // Letzter bestaedigter Treffer (Sekunden seit Boot)
    unsigned long firstSeen;     // Erster Treffer
    unsigned long onlineSince;   // Beginn aktuelle Online-Phase
    unsigned long offlineSince;  // Beginn aktuelle Offline-Phase
    uint32_t openPortBits;       // Bitmask Port-Scan-Ergebnisse
    bool     portsScanned;
    uint16_t lastSuccessPort;    // Letzter Port auf dem isOnline() erfolgreich war (adaptiver Rescan)
    // --- Zustand (RAM-only, nicht persistent) ---
    bool     active;        // Aktuell online
    bool     changed;       // Dirty-Flag: NVS-Flush noetig
    // --- Worker-State (RAM-only) ---
    bool     confirmed;     // true = mind. CONFIRM_THRESHOLD Treffer oder MAC bekannt
    uint8_t  probeSeen;     // Treffer-Zaehler in Kandidaten-Phase
    uint8_t  probeMiss;     // Fehlversuchs-Zaehler (Hysterese fuer Offline und Kandidaten-Verwurf)
    bool     enrichQueued;  // true = bereits in Enrichment-Queue eingetragen
};

// Event-Typen
#define EV_NEW      1
#define EV_ONLINE   2
#define EV_OFFLINE  3
#define EV_IPCHG    4

struct NetEvent {
    unsigned long ts;    // millis()/1000
    uint8_t  type;
    char     ip[16];
    char     info[36];   // MAC, "altIP->neuIP" (max 15+2+15=32+1), etc.
};

Device   devs[MAX_DEVICES];
int      devCount = 0;

NetEvent evLog[MAX_EVENTS];
int      evHead  = 0;   // naechster Schreib-Index
int      evTotal = 0;   // Gesamtanzahl (fuer UI)

// ================================================================
//  GLOBALE STATE
// ================================================================
Preferences   prefs;
WiFiManager   wifiManager;
WebServer     webServer(80);

String        deviceName        = DEVICE_NAME;
HardwareInfo hwInfo;
String        hubHost           = HUB_HOST;
int           hubPort           = HUB_PORT;
unsigned long lastHeartbeat     = 0;
unsigned long heartbeatInterval = (unsigned long)DEFAULT_INTERVAL_S * 1000UL;
bool          otaPending        = false;
String        otaUrl            = "";

int           scanTimeoutMs     = 200;   // pro Port — kurz halten
String        subnetBase        = "";
unsigned long lastNvsSave       = 0;

// ── FritzBox TR-064 Integration (v1.6.0) ─────────────────────────
// Periodischer Pull der Geraeteliste via X_AVM-DE_GetHostListPath
// (Service urn:dslforum-org:service:Hosts:1). Liefert Inventar/Praesenz
// fuer Geraete die TCP-FastScan nicht zuverlaessig findet (Echo, Handy,
// Tablet, Watch, IoT-Clients - siehe Review). HTTP-Digest-Auth optional,
// falls die FritzBox TR-064-Zugriff nicht ohne Login erlaubt.
bool          frbEnabled       = false;
String        frbHost          = "";          // leer = <subnet>.1
String        frbUser          = "";
String        frbPass          = "";
unsigned long frbIntervalMs    = 300000UL;     // 5 Minuten
unsigned long lastFrbPoll      = 0;
String        frbStatus        = "Noch nicht ausgefuehrt";
int           frbLastCount     = 0;
int           frbLastNew       = 0;
// Diagnosefelder (Review 9): letzter HTTP-Status, ob Digest-Auth
// versucht/benoetigt wurde, und der zuletzt aufgeloeste HostListPath.
int           frbLastHttpCode  = 0;
bool          frbLastAuthUsed  = false;   // 401 erhalten -> Digest versucht
bool          frbLastAuthOk    = false;   // Digest-Retry war erfolgreich (200)
String        frbLastPath      = "";

// Ring-Scan State
int           ringIp            = SCAN_START;
bool          ringRunning       = true;
unsigned long lastRingTick      = 0;
int           ringScanCount     = 0;

// Mini-Log: letzte 5 Scan-Ergebnisse fuer Tab-1-Anzeige
#define RING_LOG_SIZE 5
struct RingLogEntry { char ip[16]; bool found; unsigned long ms; char info[24]; };
RingLogEntry  ringLog[RING_LOG_SIZE];
int           ringLogHead = 0;

// SSE
static WiFiClient sseCli;
static bool       sseAlive      = false;
static unsigned long sseLastPush = 0;

// ================================================================
//  OUI VENDOR TABELLE (erste 3 Bytes als Hex-String)
// ================================================================
struct OuiEntry { const char* oui; const char* vendor; };
static const OuiEntry OUI_TABLE[] = {
    {"002354", "AVM"},       {"3C3786", "AVM"},       {"D850E6", "AVM"},
    {"E0CBEE", "AVM"},       {"B42200", "AVM"},       {"9C2170", "AVM"},
    {"A41B91", "Apple"},     {"3C0754", "Apple"},     {"F0B479", "Apple"},
    {"B8E856", "Samsung"},   {"8CCE4E", "Samsung"},   {"3C28FD", "Samsung"},
    {"68B599", "Xiaomi"},    {"F4F5DB", "Xiaomi"},    {"50EC50", "Xiaomi"},
    {"24A16E", "Espressif"}, {"84F703", "Espressif"}, {"A89FC9", "Espressif"},
    {"B4E842", "Google"},    {"F88FCA", "Amazon"},    {"74C246", "Amazon"},
    {"B827EB", "Raspberry"}, {"DC8B28", "Raspberry"}, {"E45F01", "Raspberry"},
    {"001EE3", "Synology"},  {"001132", "Synology"},  {"000AE4", "Synology"},
    {"001BD4", "HP"},        {"3C4A92", "HP"},
    {"000477", "Brother"},   {"00304F", "Brother"},
    {"88E3AB", "TP-Link"},   {"50D4F7", "TP-Link"},
    {"001000", "Ubiquiti"},  {"044BED", "Ubiquiti"},
    {"EC21E5", "Shelly"},    {"30AEA4", "Shelly"},
    {"68C63A", "Meross"},    {"48E1E9", "Meross"},
    {"94652D", "OnePlus"},   {"A0DB71", "OnePlus"},
    {"002077", "Kyocera"},   {"000726", "Kyocera"},
    {"001A11", "Google"},    {"F4F5E8", "Google"},
    {"18B4BE", "Nest"},      {"64D154", "Nest"},
    {"5CF5DA", "Espressif"}, {"BCDDC2", "Espressif"},
    {"000000", nullptr}  // sentinel
};

// ================================================================
//  FORWARD DECLARATIONS
// ================================================================
String   getMac();
String   getLocalIp();
String   fmtTime(unsigned long epoch);
String   toMdnsName(const String& name);
String   escJ(const char* s);
void     addEvent(uint8_t type, const char* ip, const char* info);
void     ssePush(const char* event, const String& data);
void     ssePushDeviceUpdate(const char* ip);
void     enrichEnqueue(const char* ip);
void     discoveryWorker();
void     presenceWorker();
void     enrichmentWorker();
bool     tcpProbe(const char* ip, uint16_t port, int timeoutMs);
bool     isOnline(const char* ip);
bool     isOnlinePort(const char* ip, uint16_t* hitPort);
bool     isOnlinePreferred(Device* d);
void     tryGetMac(const char* ip, Device* d);
void     tryGetHostname(const char* ip, Device* d);
void     inferDtype(Device* d);
String   lookupVendor(const char* mac);
Device*  findByMac(const char* mac);
void     mergeByMac(const char* newIp, Device* d);
String   md5hex(const String& in);
String   extractXmlTag(const String& src, const char* tag);
String   digestParam(const String& hdr, const char* key);
bool     fritzboxRequest(const String& host, const String& path, const String& soapAction, const String& body, String& response);
void     fritzboxPoll();
Device*  findOrCreate(const char* ip);
void     saveDevice(Device* d);
void     flushDirtyDevices();
void     loadDevices();
void     saveSettings();
void     loadSettings();
void     doRingTick();
String   doPing(const char* ip);
String   doPortScan(const char* ip);
String   buildDevicesJson(bool onlyOnline);
String   buildEventsJson();
String   buildRingLog();
void     handleRoot();
void     handleOtaPage();
void     handleOtaUpload();
void     handleOtaUploadFinish();
void     handleNotFound();
void     handleApiSse();
void     handleApiDevices();
void     handleApiSave();
void     handleApiDelete();
void     handleApiPing();
void     handleApiPortScan();
void     handleApiSettings();
void     handleApiFritzboxNow();
void     handleApiStatus();
void     handleApiEvents();
void     setupWebServer();
void     checkResetButton();
void     setupWifi();
String   buildHeartbeat();
void     sendHeartbeat();
void     performOta(const String& url);

// ================================================================
//  HILFSFUNKTIONEN
// ================================================================
String getMac() { String m=WiFi.macAddress(); m.replace(":",""); m.toUpperCase(); return m; }
String getLocalIp() { return WiFi.localIP().toString(); }
String toMdnsName(const String& n) {
    String o=""; String s=n; s.toLowerCase();
    for(int i=0;i<(int)s.length();i++){
        char c=s[i];
        if((c>='a'&&c<='z')||(c>='0'&&c<='9')) o+=c;
        else if(c=='-'||c==' '||c=='_') o+='-';
    }
    while(o.startsWith("-")) o=o.substring(1);
    while(o.endsWith("-")) o=o.substring(0,o.length()-1);
    if(o.length()>63) o=o.substring(0,63);
    return o.length()>0?o:"esp32";
}
String fmtTime(unsigned long epoch) {
    if(epoch==0) return "-";
    unsigned long s=millis()/1000UL;
    unsigned long ago=(s>epoch)?(s-epoch):0;
    if(ago<60) return String(ago)+"s";
    if(ago<3600) return String(ago/60)+"min";
    if(ago<86400) return String(ago/3600)+"h "+String((ago%3600)/60)+"min";
    return String(ago/86400)+"d "+String((ago%86400)/3600)+"h";
}
String escJ(const char* s) {
    String o="";
    for(int i=0;s[i];i++){
        char c=s[i];
        if(c=='"') o+="\\\"";
        else if(c=='\\') o+="\\\\";
        else if(c=='\n'||c=='\r') o+=" ";
        else o+=c;
    }
    return o;
}

// ================================================================
//  EVENT-LOG
// ================================================================
void addEvent(uint8_t type, const char* ip, const char* info) {
    NetEvent& ev = evLog[evHead % MAX_EVENTS];
    // Echte Unix-Zeit (Epoch) statt Boot-relativer Sekunden (v1.6.3),
    // damit das Event-Log die tatsaechliche Uhrzeit zeigen kann.
    // Vor NTP-Sync liefert time(nullptr) ~0 (1.1.1970) - unkritisch.
    ev.ts   = (unsigned long)time(nullptr);
    ev.type = type;
    strncpy(ev.ip,   ip,   15);   ev.ip[15]   = 0;
    strncpy(ev.info, info, 35);   ev.info[35] = 0;
    evHead  = (evHead + 1) % MAX_EVENTS;
    evTotal++;
    // SSE push
    String d = "{\"t\":"+String(ev.ts)+",\"type\":"+String(type)+",\"ip\":\""+String(ip)+"\",\"info\":\""+escJ(info)+"\"}";
    ssePush("event", d);
}

String buildEventsJson() {
    int cnt = min(evTotal, MAX_EVENTS);
    String j = "[";
    // neueste zuerst: rueckwaerts durch Ringpuffer
    for(int i=0;i<cnt;i++){
        int idx = ((evHead - 1 - i) + MAX_EVENTS) % MAX_EVENTS;
        NetEvent& ev = evLog[idx];
        if(i>0) j+=",";
        const char* typeName = ev.type==EV_NEW?"NEU":ev.type==EV_ONLINE?"ONLINE":ev.type==EV_OFFLINE?"OFFLINE":"IP-CHG";
        j+="{\"t\":"+String(ev.ts)+",\"type\":\""+typeName+"\",\"ip\":\""+escJ(ev.ip)+"\",\"info\":\""+escJ(ev.info)+"\"}";
    }
    return j+"]";
}

// ================================================================
//  SSE
// ================================================================
void ssePush(const char* event, const String& data) {
    if(!sseAlive) return;
    if(!sseCli.connected()) { sseAlive=false; return; }
    sseCli.print(String("event:")+event+"\ndata:"+data+"\n\n");
    sseLastPush = millis();
}
void ssePushDeviceUpdate(const char* ip) {
    // Einzelnes Geraet als SSE senden
    Device* d = nullptr;
    for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0){ d=&devs[i]; break; }
    if(!d) return;
    String j = "{\"ip\":\""+String(d->ip)+"\","
               "\"active\":"+String(d->active?"true":"false")+","
               "\"hn\":\""+escJ(d->hostname)+"\","
               "\"mac\":\""+String(d->mac)+"\","
               "\"vendor\":\""+escJ(d->vendor)+"\","
               "\"dtype\":"+String(d->dtype)+","
               "\"onlineSince\":\""+fmtTime(d->onlineSince)+"\","
               "\"offlineSince\":\""+fmtTime(d->offlineSince)+"\"}";;
    ssePush("device", j);
}

// ================================================================
//  TCP PROBE (non-blocking)
// ================================================================
bool tcpProbe(const char* ip, uint16_t port, int timeoutMs) {
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port        = htons(port);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s<0) return false;
    fcntl(s, F_SETFL, fcntl(s,F_GETFL,0)|O_NONBLOCK);
    connect(s,(struct sockaddr*)&addr,sizeof(addr));
    fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds);
    struct timeval tv = {0,(suseconds_t)(timeoutMs*1000L)};
    bool ok = false;
    if(select(s+1,NULL,&fds,NULL,&tv) > 0) {
        // SO_ERROR pruefen: select() meldet auch fehlgeschlagene Connects als "writable".
        // Ohne diesen Check entstehen False Positives (Geraet scheint online, ist es nicht).
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen);
        ok = (err == 0);
    }
    close(s);
    return ok;
}

// Fast-Probe-Ports fuer isOnline() - bewusst auf 5 beschraenkt.
// Begruendung:
//   80/443  = Router, NAS, Webcams, ESPs, alle Web-UIs
//   22      = SSH (Linux-Server, NAS, Proxmox, Raspberry)
//   53      = DNS (Router, Pi-hole, AdGuard)
//   8093    = ESP-Hub / ioBroker (projektspezifisch)
// Weniger Ports = schnellerer Ring-Scan = responsivere UI.
// Breiteren Portscan gibt es per Button im UI (20 Ports).
// ICMP wurde entfernt: raw sockets auf ESP32 Core 3.x verursachen
// TWDT-Abbrueche und false positives (Geister-IPs).
// Tiefenscan-Portliste (20 Ports, manueller Portscan-Button).
// Bit i in Device.openPortBits entspricht PORT_LIST[i].
// Wird auch fuer die 2. Presence-Stufe genutzt (siehe isOnlinePreferred).
static const uint16_t PORT_LIST[]  = {21,22,23,25,53,80,110,139,143,443,445,554,3389,5000,5900,7547,8080,8443,8888,9100};
static const int      PORT_LIST_CNT = 20;

// Optionales Consumer-/Media-Zusatzprofil (Review-Empfehlung):
// Chromecast/Google-Cast (8008/8009), alternative HTTPS-UIs (8443),
// alternative Web-/Streaming-Ports (8888). Wird NUR als letzte Stufe
// fuer bereits bestaetigte Geraete versucht (isOnlinePreferred), nicht
// im Discovery-FastScan - haelt den Ring-Scan fuer unbekannte IPs schnell.
static const uint16_t CONSUMER_PORTS[] = {8008, 8009, 8443, 8888};
static const int CONSUMER_PORT_COUNT = 4;

// "Balanced Home"-Profil aus dem Review: deckt Router, NAS, Windows/SMB,
// Drucker und Kameras zusaetzlich ab - wichtig fuer reale Heimnetze
// mit gemischten Geraeten (nicht nur Infrastruktur).
//   80/443  = Web/HTTPS (Router, NAS, ESPs, Kameras, Drucker-WebUI)
//   22      = SSH
//   53      = DNS (Router, Pi-hole)
//   8093    = ESP-Hub/ioBroker
//   8080    = alternative WebUIs
//   445/139 = SMB (Windows/NAS)
//   554     = RTSP (Kameras)
//   9100    = JetDirect (Drucker)
static const uint16_t SCAN_PORTS[] = {80, 443, 22, 53, 8093, 8080, 445, 139, 554, 9100};
static const int SCAN_PORT_COUNT = 10;

// Prueft ob eine IP erreichbar ist (TCP-only, 5 Ports, yield() zwischen Ports).
// TCP ist auf ESP32 stabiler als ICMP raw sockets und reicht fuer die
// meisten Heimnetz-Geraete (Router, Server, NAS, ESPs, Drucker).
// Handys/Tablets ohne offene Ports sind via Ping-Button prüfbar.
bool isOnline(const char* ip) {
    return isOnlinePort(ip, nullptr);
}

// Wie isOnline(), liefert zusaetzlich den Port des ersten Treffers in *hitPort
// (0 wenn keiner). Wird von Presence genutzt um den zuletzt erfolgreichen
// Port zuerst zu pruefen (adaptiver Rescan, siehe lastSuccessPort).
bool isOnlinePort(const char* ip, uint16_t* hitPort) {
    for(int i = 0; i < SCAN_PORT_COUNT; i++) {
        if(tcpProbe(ip, SCAN_PORTS[i], scanTimeoutMs)) {
            if(hitPort) *hitPort = SCAN_PORTS[i];
            return true;
        }
        yield();
        webServer.handleClient();
    }
    if(hitPort) *hitPort = 0;
    return false;
}

// Praeferierter Online-Check fuer bestaetigte Geraete (3 Stufen):
//  1. lastSuccessPort   - zuletzt erfolgreicher Port (schnellster Pfad)
//  2. openPortBits      - alle frueher per Tiefenscan gefundenen offenen
//                          Ports (PORT_LIST), bevor auf den generischen
//                          FastScan zurueckgefallen wird
//  3. SCAN_PORTS        - generischer FastScan-Fallback (isOnlinePort)
//  4. CONSUMER_PORTS    - letzte Chance fuer TV/Echo/Cast-Geraete
// Jede erfolgreiche Stufe aktualisiert lastSuccessPort fuer den naechsten
// Durchlauf. Stufen 2+4 laufen NUR fuer bestaetigte Geraete - der
// Discovery-FastScan fuer unbekannte IPs bleibt unveraendert klein.
bool isOnlinePreferred(Device* d) {
    // Stufe 1: zuletzt erfolgreicher Port
    if(d->lastSuccessPort != 0) {
        if(tcpProbe(d->ip, d->lastSuccessPort, scanTimeoutMs)) return true;
        yield();
        webServer.handleClient();
    }

    // Stufe 2: bekannte offene Ports aus frueherem Tiefenscan
    if(d->portsScanned && d->openPortBits != 0) {
        for(int i=0;i<PORT_LIST_CNT;i++){
            if(!((d->openPortBits>>i)&1)) continue;
            uint16_t p = PORT_LIST[i];
            if(p == d->lastSuccessPort) continue; // schon in Stufe 1 probiert
            if(tcpProbe(d->ip, p, scanTimeoutMs)) {
                d->lastSuccessPort = p;
                return true;
            }
            yield();
            webServer.handleClient();
        }
    }

    // Stufe 3: generischer FastScan-Fallback
    uint16_t hit = 0;
    if(isOnlinePort(d->ip, &hit)) {
        if(hit != 0) d->lastSuccessPort = hit;
        return true;
    }

    // Stufe 4: optionale Consumer-/Media-Ports (TV/Echo/Cast)
    for(int i=0;i<CONSUMER_PORT_COUNT;i++){
        if(tcpProbe(d->ip, CONSUMER_PORTS[i], scanTimeoutMs)) {
            d->lastSuccessPort = CONSUMER_PORTS[i];
            return true;
        }
        yield();
        webServer.handleClient();
    }
    return false;
}

// ================================================================
//  MAC-ERMITTLUNG per ARP
// ================================================================
// Versucht nach einem TCP-Treffer die MAC-Adresse des Zielgeraets
// aus dem lwIP-ARP-Cache zu lesen (etharp_find_addr).
// Da ein TCP-Connect einen ARP-Lookup ausloest, ist der Cache danach
// meist gefuellt. Dies ist "best effort" - core-/lwIP-abhaengig,
// nicht garantiert. Klappt es nicht, bleibt mac[0] == 0.
// Aktivierbar/deaktivierbar via FEATURE_ARP_MAC (oben).
void tryGetMac(const char* ip, Device* d) {
    if(d->mac[0]!=0) return; // MAC bereits bekannt, kein erneuter Lookup
#if FEATURE_ARP_MAC
    // ARP-Cache abfragen. Funktioniert nach TCP-Connect, da lwIP
    // die Adresse aufgeloest hat. Schlaegt der Lookup fehl, bleibt
    // mac leer und wird beim naechsten Treffer erneut versucht.
    ip4_addr_t target;
    target.addr = inet_addr(ip);
    struct eth_addr* ethRet = nullptr;
    const ip4_addr_t* ipRet = nullptr;
    err_t err = etharp_find_addr(nullptr, &target, &ethRet, &ipRet);
    if(err == ERR_OK && ethRet) {
        snprintf(d->mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            ethRet->addr[0], ethRet->addr[1], ethRet->addr[2],
            ethRet->addr[3], ethRet->addr[4], ethRet->addr[5]);
        String vendor = lookupVendor(d->mac);
        if(vendor.length()>0) strncpy(d->vendor, vendor.c_str(), 23);
        d->changed = true;
        Serial.printf("[ARP] %s -> MAC %s (%s)\n", ip, d->mac, vendor.c_str());
    } else {
        // Diagnose: ARP-Cache hatte (noch) keinen Eintrag fuer diese IP.
        // Best-effort - wird beim naechsten Enrichment-Versuch erneut probiert.
        Serial.printf("[ARP] %s -> kein Cache-Eintrag (err=%d)\n", ip, (int)err);
    }
#else
    (void)ip; (void)d; // ARP deaktiviert - FEATURE_ARP_MAC = 0 setzen zum Debuggen
#endif
}

String lookupVendor(const char* mac) {
    // MAC hat Format "AA:BB:CC:..."
    char oui[7] = {0};
    // Erste 6 Hex-Zeichen ohne Doppelpunkte
    int j=0;
    for(int i=0;i<18&&j<6;i++){
        if(mac[i]!=':') oui[j++]=toupper(mac[i]);
    }
    oui[6]=0;
    for(int i=0; OUI_TABLE[i].vendor!=nullptr; i++){
        if(strncmp(OUI_TABLE[i].oui, oui, 6)==0) return String(OUI_TABLE[i].vendor);
    }
    return "";
}

// ================================================================
//  HOSTNAME via HTTP
// ================================================================
// Versucht den Hostnamen des Zielgeraets via HTTP zu ermitteln.
// Strategie: GET / auf Port 80/8080/8093, dann Server-Header und
// <title>-Tag auswerten. Wird nur ausgefuehrt wenn hostname noch
// leer ist - also max. einmal pro Geraet (solange kein Neustart).
// Aktivierbar/deaktivierbar via FEATURE_HTTP_NAME.
void tryGetHostname(const char* ip, Device* d) {
    if(strlen(d->hostname)>0 && strcmp(d->hostname,"-")!=0) return; // schon bekannt
    // HTTP HEAD oder GET auf Port 80/8080/8093
#if FEATURE_HTTP_NAME
    // Timeout sehr kurz halten! Diese Funktion laeuft im loop()-Tick.
    // Lange Blockaden (> 5s) loesen den Task-Watchdog-Timer (TWDT) aus.
    // Gesamtbudget: max 2 Ports x (100ms probe + 600ms read) = 1,4s
    // Nur Port 80, max 500ms total. Schnell halten um TWDT zu vermeiden.
    const uint16_t httpPorts[] = {80};
    for(int pi=0;pi<1;pi++){
        if(!tcpProbe(ip, httpPorts[pi], 100)) { yield(); continue; }
        WiFiClient cl; cl.setTimeout(400);  // war 1000ms
        if(!cl.connect(ip, httpPorts[pi])) { yield(); continue; }
        cl.printf("GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", ip);
        unsigned long t0=millis(); String resp=""; bool gotTitle=false;
        while(cl.connected() && millis()-t0 < 600) {  // war 1500ms
            yield();  // TWDT reset - verhindert Reboot
            webServer.handleClient();
            if(!cl.available()) { delay(5); continue; }
            String line=cl.readStringUntil('\n');
            resp+=line;
            if(line.startsWith("Server:") && strlen(d->hostname)==0){
                String srv=line.substring(7); srv.trim();
                strncpy(d->hostname, srv.substring(0,47).c_str(), 47);
                d->changed=true;
            }
            int ti=resp.indexOf("<title>"); int te=resp.indexOf("</title>");
            if(ti>=0&&te>ti&&!gotTitle){
                String title=resp.substring(ti+7,te); title.trim();
                strncpy(d->hostname, title.substring(0,47).c_str(), 47);
                d->changed=true; gotTitle=true; break;
            }
            if(resp.length()>2048) break;  // war 4096
        }
        cl.stop();
        yield();
        if(strlen(d->hostname)>0) break;
    }
#else
    (void)ip; (void)d; // HTTP-Hostname deaktiviert
#endif
}

// ================================================================
//  GERAETETYP-HEURISTIK
// ================================================================
// Setzt dtype automatisch anhand offener Ports und Vendor-Hinweisen.
// Wird nur ausgefuehrt wenn dtype == 0 (unbekannt / noch nicht gesetzt).
// Manuell gesetzte Werte (dtype != 0) werden nie ueberschrieben.
// Heuristik - kein Anspruch auf 100% Korrektheit.
// Geraetetyp-Codes (siehe auch DN[]/DE[] in der UI):
//  0=?  1=Router 2=PC/Server 3=ESP/IoT 4=Phone 5=Drucker 6=TV 7=NAS
//  8=Kamera 9=Switch 10=Tablet 11=Speaker(Alexa/Google/Nest) 12=SmartPlug
//  13=Vacuum 14=Bridge/Hub 15=Repeater/AP
void inferDtype(Device* d) {
    if(d->dtype != 0) return; // Bereits gesetzt (manuell oder frueherer Scan)
    uint32_t b = d->openPortBits;
    // Port-Bit-Mapping muss mit PORT_LIST uebereinstimmen (doPortScan)
    // Bits: 0=21,1=22,2=23,3=25,4=53,5=80,6=110,7=139,8=143,9=443,10=445,11=554,12=3389,13=5000,14=5900,15=7547,16=8080,17=8443,18=8888,19=9100
    bool has53  = (b>>4)&1;   // DNS
    bool has80  = (b>>5)&1;
    bool has443 = (b>>9)&1;
    bool has445 = (b>>10)&1;
    bool has139 = (b>>7)&1;
    bool has554 = (b>>11)&1;  // RTSP
    bool has9100= (b>>19)&1;  // Druck

    // ── Hostname-basierte Erkennung (zuverlaessigste Quelle) ──────
    String hn = String(d->hostname); hn.toLowerCase();
    if(hn.indexOf("repeater")>=0 || hn.indexOf("fritz!repeater")>=0)
        { d->dtype=15; return; } // Repeater/AP (vor "fritz"-Check, sonst Router)
    if(hn.indexOf("fritz")>=0 || hn.indexOf("avm")>=0)
        { d->dtype=1; return; }   // FritzBox/AVM-Router
    if(hn.indexOf("synology")>=0 || hn.indexOf("diskstation")>=0)
        { d->dtype=7; return; }   // Synology NAS
    if(hn.indexOf("proxmox")>=0 || hn.indexOf("pve")>=0)
        { d->dtype=2; return; }   // Server
    if(hn.indexOf("printer")>=0 || hn.indexOf("kyocera")>=0 || hn.indexOf("brother")>=0
       || hn.indexOf("hp laser")>=0)
        { d->dtype=5; return; }   // Drucker
    if(hn.indexOf("cam")>=0 || hn.indexOf("ipcam")>=0 || hn.indexOf("camera")>=0)
        { d->dtype=8; return; }   // Kamera
    if(hn.indexOf("hue")>=0)
        { d->dtype=14; return; }  // Philips Hue Bridge
    if(hn.indexOf("echo")>=0 || hn.indexOf("alexa")>=0)
        { d->dtype=11; return; }  // Amazon Echo / Alexa
    if(hn.indexOf("ipad")>=0 || hn.indexOf("tablet")>=0 || hn.indexOf("tab-")>=0)
        { d->dtype=10; return; }  // Tablet
    // ── v1.6.6: Neue Muster (Review 4) - FritzBox liefert jetzt oft
    // brauchbare Namen wie "iPhone", "Watch", "SamsungTVSchlafzimmer",
    // "LAPTOP-MAQN8H85", "xiaomirobi" - diese vorher ungenutzt.
    if(hn.indexOf("iphone")>=0)
        { d->dtype=4; return; }   // iPhone -> Phone
    if(hn.indexOf("watch")>=0)
        { d->dtype=4; return; }   // Smartwatch -> Phone-Kategorie (kein eigener Typ)
    if(hn.indexOf("robi")>=0)
        { d->dtype=13; return; }  // z.B. "xiaomirobi" -> Saugroboter (vor TV/Phone-Checks)
    if(hn.indexOf("vacuum")>=0 || hn.indexOf("roborock")>=0 || hn.indexOf("robot")>=0)
        { d->dtype=13; return; }  // Saugroboter
    if(hn.indexOf("plug")>=0 || hn.indexOf("steckdose")>=0)
        { d->dtype=12; return; }  // Smart Plug
    if(hn.indexOf("samsungtv")>=0 || hn.indexOf("philipstv")>=0 || hn.indexOf("philips tv")>=0
       || hn.indexOf("lgtv")>=0 || hn.indexOf("smarttv")>=0 || hn.indexOf("-tv")>=0
       || hn.indexOf("tv-")>=0 || hn.indexOf("_tv")>=0 || hn.indexOf(" tv")>=0)
        { d->dtype=6; return; }   // Smart-TV (Samsung/Philips/LG + "...tv" mit Trenner,
                                  // vermeidet False-Positives bei zufaelligen "tv"-Substrings
    if(hn.indexOf("laptop")>=0 || hn.indexOf("notebook")>=0)
        { d->dtype=2; return; }   // Laptop -> PC-Kategorie
    if(hn.indexOf("esp")>=0 || hn.indexOf("shelly")>=0)
        { d->dtype=3; return; }   // ESP/Shelly

    // ── Port-Heuristik (aus Port-Scan, wenn durchgefuehrt) ────────
    if(has53&&has80&&has443) { d->dtype=1; return; }   // Router (DNS+HTTP+HTTPS)
    if(has554)               { d->dtype=8; return; }   // Kamera (RTSP)
    if(has9100)              { d->dtype=5; return; }   // Drucker (JetDirect)
    if(has445||has139)       { d->dtype=2; return; }   // PC/NAS (SMB)
    if(has80||has443)        { d->dtype=2; return; }   // Web-fähiges Geraet

    // ── Vendor-basiert (aus OUI-Tabelle) ──────────────────────────
    // Hinweis: Vendor allein ist die unsicherste Quelle (z.B. Xiaomi =
    // Phone ODER Vacuum ODER SmartPlug). Hostname/Ports haben Vorrang
    // (siehe oben); Vendor ist nur der letzte Fallback.
    String v = String(d->vendor);
    if(v=="AVM")             { d->dtype=1; return; }   // Router/Repeater (ohne Hostname-Hinweis: Router)
    if(v=="Espressif"||v=="Shelly") { d->dtype=3; return; } // ESP/IoT
    if(v=="Meross")          { d->dtype=12; return; }  // Smart Plug
    if(v=="Apple"||v=="Samsung"||v=="Xiaomi"||v=="OnePlus") { d->dtype=4; return; } // Phone (Default)
    if(v=="Synology")        { d->dtype=7; return; }
    if(v=="Brother"||v=="HP"||v=="Kyocera") { d->dtype=5; return; }
    if(v=="Raspberry")       { d->dtype=2; return; }
    // Korrektur ggue. v1.5.8: Amazon/Google/Nest sind im Heimnetz meist
    // Echo/Google-Home-Lautsprecher oder Hubs, NICHT TVs.
    if(v=="Amazon")          { d->dtype=11; return; }  // Alexa/Echo (Speaker)
    if(v=="Google"||v=="Nest") { d->dtype=11; return; } // Google Home/Nest (Speaker/Hub)
}

// ================================================================
//  PERSISTENZ
// ================================================================
// Sucht ein Geraet nach MAC-Adresse.
// Wird nach erfolgreichem ARP-Lookup aufgerufen um IP-Wechsel zu erkennen.
Device* findByMac(const char* mac) {
    if(!mac || !mac[0]) return nullptr;
    for(int i=0;i<devCount;i++)
        if(devs[i].mac[0] && strcmp(devs[i].mac, mac)==0) return &devs[i];
    return nullptr;
}

// Prueft nach MAC-Ermittlung ob bereits ein Geraet mit dieser MAC
// unter einer ANDEREN IP bekannt ist (= IP-Wechsel durch DHCP).
// Wenn ja: IP aktualisieren und IP-CHG Event loggen.
// Wenn nein: nichts tun (regulaerer Fall).
void mergeByMac(const char* newIp, Device* d) {
    if(!d->mac[0]) return; // noch keine MAC bekannt
    Device* existing = findByMac(d->mac);
    if(!existing || existing == d) return; // kein anderes Geraet mit dieser MAC
    if(strcmp(existing->ip, newIp)==0) return; // gleiche IP, kein Wechsel
    // IP-Wechsel erkannt: alten Eintrag aktualisieren
    char oldIp[16]; strncpy(oldIp, existing->ip, 15);
    strncpy(existing->ip, newIp, 15);
    existing->changed = true;
    // Info-String "alt->neu" fuer Event-Log (volle IPv4-Adressen,
    // max 15+2+15=32 Zeichen, Puffer 36 -> kein Abschneiden mehr)
    char info[36]; snprintf(info, sizeof(info), "%s->%s", oldIp, newIp);
    addEvent(EV_IPCHG, newIp, info);
    ssePushDeviceUpdate(newIp);
}

Device* findOrCreate(const char* ip) {
    for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0) return &devs[i];
    if(devCount>=MAX_DEVICES) return nullptr;
    Device* d=&devs[devCount++];
    memset(d,0,sizeof(Device));
    strncpy(d->ip,ip,15);
    // Worker-State-Felder explizit initialisieren (memset setzt bool auf 0/false)
    d->confirmed    = false;
    d->probeSeen    = 0;
    d->probeMiss    = 0;
    d->enrichQueued = false;
    d->lastSuccessPort = 0;
    return d;
}

// ================================================================
//  FRITZBOX TR-064 INTEGRATION (v1.6.0)
// ================================================================
//
// Holt periodisch die Geraeteliste der FritzBox per TR-064/SOAP
// (Service "Hosts:1", Action "X_AVM-DE_GetHostListPath") und merged
// sie per MAC-Adresse in devs[]. Damit werden auch "stille" Geraete
// (Echo, Handy, Tablet, Watch, IoT) als bestaetigtes Inventar gefuehrt
// und vom PresenceWorker weiterhin per TCP ueberwacht (sofern moeglich).
//
// Ablauf:
//  1. SOAP-POST an /upnp/control/hosts -> liefert Pfad zu einer
//     generierten XML-Datei mit allen Hosts.
//  2. GET dieser XML-Datei -> <Item>...</Item> Bloecke mit IP/MAC/
//     HostName/Active.
//  3. Merge: bekannte MAC -> Update, unbekannte MAC -> neues Geraet
//     (confirmed=true, EV_NEW "FritzBox").
//
// HTTP-Digest-Auth (RFC 2617, MD5) wird automatisch versucht falls
// die FritzBox mit 401 antwortet und Zugangsdaten konfiguriert sind.
// Ohne Zugangsdaten funktioniert es, wenn in der FritzBox unter
// "Heimnetz -> Netzwerk -> Netzwerkeinstellungen" die Option
// "Zugriff fuer Anwendungen zulassen" / UPnP-Statusinfo aktiv ist.

// MD5-Hex-Helper (fuer Digest-Auth-Berechnung)
String md5hex(const String& in) {
    MD5Builder md5;
    md5.begin();
    md5.add(in);
    md5.calculate();
    return md5.toString();
}

// Extrahiert den Inhalt von <tag>...</tag> aus einem XML/SOAP-String.
// Sehr einfacher String-Parser - reicht fuer die flachen TR-064-Antworten.
String extractXmlTag(const String& src, const char* tag) {
    String open  = "<"  + String(tag) + ">";
    String close = "</" + String(tag) + ">";
    int s = src.indexOf(open);
    if(s < 0) return "";
    s += open.length();
    int e = src.indexOf(close, s);
    if(e < 0) return "";
    String v = src.substring(s, e);
    v.trim();
    return v;
}

// Liest einen einzelnen Parameter aus einem WWW-Authenticate: Digest ...
// Header (z.B. realm="...", nonce="...", qop=auth).
String digestParam(const String& hdr, const char* key) {
    String k = String(key) + "=\"";
    int s = hdr.indexOf(k);
    if(s >= 0) {
        s += k.length();
        int e = hdr.indexOf("\"", s);
        if(e < 0) return "";
        return hdr.substring(s, e);
    }
    // unquoted Variante (z.B. qop=auth ohne Anfuehrungszeichen)
    k = String(key) + "=";
    s = hdr.indexOf(k);
    if(s < 0) return "";
    s += k.length();
    int e = hdr.indexOf(",", s);
    if(e < 0) e = hdr.length();
    String v = hdr.substring(s, e);
    v.trim();
    return v;
}

// Fuehrt einen TR-064 SOAP-Request aus, mit automatischem HTTP-Digest-Auth-
// Retry falls 401 + Zugangsdaten konfiguriert sind. soapAction=="" => GET
// (zum Abholen der generierten Hostlisten-XML-Datei).
bool fritzboxRequest(const String& host, const String& path,
                      const String& soapAction, const String& body,
                      String& response) {
    // FritzOS >= 7.50: TR-064 nur noch via HTTPS auf Port 49443
    // (Port 49000/HTTP ist standardmaessig deaktiviert). Das Zertifikat
    // ist selbstsigniert -> setInsecure() (kein CA-Check, lokales Netz).
    String url = "https://" + host + ":49443" + path;
    const char* method = soapAction.length() > 0 ? "POST" : "GET";

    WiFiClientSecure sclient;
    sclient.setInsecure();
    HTTPClient http;
    http.begin(sclient, url);
    const char* hdrs[] = {"WWW-Authenticate"};
    http.collectHeaders(hdrs, 1);
    http.setTimeout(4000);
    if(soapAction.length() > 0) {
        http.addHeader("Content-Type", "text/xml; charset=\"utf-8\"");
        http.addHeader("SOAPACTION", soapAction);
    }
    int code = (soapAction.length() > 0) ? http.POST(body) : http.GET();
    frbLastHttpCode = code;
    frbLastAuthUsed = false;
    frbLastAuthOk   = false;

    if(code == 401 && frbUser.length() > 0) {
        frbLastAuthUsed = true;
        String wwwAuth = http.header("WWW-Authenticate");
        http.end();
        String realm = digestParam(wwwAuth, "realm");
        String nonce = digestParam(wwwAuth, "nonce");
        String qop   = digestParam(wwwAuth, "qop");
        if(realm.length()==0 || nonce.length()==0) return false;
        if(qop.length()==0) qop = "auth";

        String nc     = "00000001";
        String cnonce = String((uint32_t)esp_random(), HEX);
        String ha1 = md5hex(frbUser + ":" + realm + ":" + frbPass);
        String ha2 = md5hex(String(method) + ":" + path);
        String respHash = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
        String authHdr = "Digest username=\"" + frbUser + "\", realm=\"" + realm +
                          "\", nonce=\"" + nonce + "\", uri=\"" + path +
                          "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce +
                          "\", response=\"" + respHash + "\"";

        WiFiClientSecure sclient2;
        sclient2.setInsecure();
        HTTPClient http2;
        http2.begin(sclient2, url);
        http2.setTimeout(4000);
        if(soapAction.length() > 0) {
            http2.addHeader("Content-Type", "text/xml; charset=\"utf-8\"");
            http2.addHeader("SOAPACTION", soapAction);
        }
        http2.addHeader("Authorization", authHdr);
        code = (soapAction.length() > 0) ? http2.POST(body) : http2.GET();
        frbLastHttpCode = code;
        if(code == 200) { frbLastAuthOk = true; response = http2.getString(); http2.end(); return true; }
        http2.end();
        return false;
    }

    if(code == 200) { response = http.getString(); http.end(); return true; }
    http.end();
    return false;
}

// Holt die FritzBox-Hostliste und merged sie per MAC in devs[].
// Wird periodisch aus loop() aufgerufen (frbIntervalMs).
void fritzboxPoll() {
    if(WiFi.status() != WL_CONNECTED) { frbStatus = "Kein WLAN"; return; }

    String host = frbHost.length() > 0 ? frbHost : (subnetBase + ".1");

    // Schritt 1: GetHostListPath via SOAP
    String soapBody =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body><u:X_AVM-DE_GetHostListPath xmlns:u=\"urn:dslforum-org:service:Hosts:1\">"
        "</u:X_AVM-DE_GetHostListPath></s:Body></s:Envelope>";

    String resp;
    if(!fritzboxRequest(host, "/upnp/control/hosts",
        "urn:dslforum-org:service:Hosts:1#X_AVM-DE_GetHostListPath", soapBody, resp)) {
        // Diagnose: 401 ohne Erfolg = Login noetig/falsch, sonst Netzwerk/Erreichbarkeit
        if(frbLastHttpCode == 401)
            frbStatus = "Fehler: Login noetig oder falsch (HTTP 401, Digest "
                        + String(frbLastAuthUsed ? "versucht" : "nicht versucht") + ")";
        else
            frbStatus = "Fehler: GetHostListPath nicht erreichbar (HTTP " + String(frbLastHttpCode) + ")";
        Serial.println("[FRB] GetHostListPath fehlgeschlagen, HTTP=" + String(frbLastHttpCode));
        return;
    }
    String path = extractXmlTag(resp, "NewX_AVM-DE_HostListPath");
    frbLastPath = path;
    if(path.length() == 0) {
        frbStatus = "Fehler: SOAP ok (HTTP " + String(frbLastHttpCode) + "), aber kein HostListPath in Antwort";
        return;
    }

    // Schritt 2: Hostlisten-XML laden
    String list;
    if(!fritzboxRequest(host, path, "", "", list)) {
        frbStatus = "Fehler: Hostliste-Download fehlgeschlagen (HTTP " + String(frbLastHttpCode) + ")";
        Serial.println("[FRB] Hostliste-Download fehlgeschlagen: " + path + " HTTP=" + String(frbLastHttpCode));
        return;
    }
    if(list.indexOf("<Item>") < 0) {
        frbStatus = "Fehler: Hostliste leer/unerwartetes Format (Pfad " + path + ")";
        return;
    }

    // Schritt 3: <Item>...</Item> Bloecke parsen und mergen
    int total = 0, neu = 0, pos = 0;
    unsigned long bootSec = millis() / 1000UL;
    while(true) {
        int s = list.indexOf("<Item>", pos);
        if(s < 0) break;
        int e = list.indexOf("</Item>", s);
        if(e < 0) break;
        String item = list.substring(s, e);
        pos = e + 7;
        yield();
        webServer.handleClient();

        String ip   = extractXmlTag(item, "IPAddress");
        String mac  = extractXmlTag(item, "MACAddress");
        String name = extractXmlTag(item, "HostName");
        String act  = extractXmlTag(item, "Active");
        if(ip.length() == 0 || mac.length() == 0) continue;
        mac.toUpperCase();
        bool active = (act == "1");
        total++;

        // Geraet per MAC suchen, sonst per IP, sonst neu anlegen
        Device* d = findByMac(mac.c_str());
        if(!d) for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip, ip.c_str())==0){ d=&devs[i]; break; }
        if(!d) d = findOrCreate(ip.c_str());
        if(!d) continue; // Tabelle voll

        // IP-Wechsel erkennen (bekannte MAC, andere IP als bisher)
        if(strcmp(d->ip, ip.c_str()) != 0) {
            char oldIp[16]; strncpy(oldIp, d->ip, 15); oldIp[15]=0;
            strncpy(d->ip, ip.c_str(), 15); d->ip[15]=0;
            d->changed = true;
            char info[36]; snprintf(info, sizeof(info), "%s->%s", oldIp, ip.c_str());
            addEvent(EV_IPCHG, d->ip, info);
        }

        // MAC + Vendor uebernehmen falls noch unbekannt
        if(d->mac[0]==0 && mac.length()>0) {
            strncpy(d->mac, mac.c_str(), 17); d->mac[17]=0;
            String vendor = lookupVendor(d->mac);
            if(vendor.length()>0) strncpy(d->vendor, vendor.c_str(), 23);
            d->changed = true;
        }
        // Hostname von der FritzBox uebernehmen (z.B. "Echo-Dot-Bad")
        if(strlen(d->hostname)==0 && name.length()>0) {
            strncpy(d->hostname, name.c_str(), 47); d->hostname[47]=0;
            d->changed = true;
        }
        if(d->dtype==0) inferDtype(d);

        // Bestaetigen falls noch Kandidat / unbekannt
        if(!d->confirmed) {
            d->confirmed = true;
            if(d->firstSeen==0) d->firstSeen = bootSec;
            addEvent(EV_NEW, d->ip, "FritzBox");
            neu++;
        }

        // Praesenz: FritzBox "aktiv" darf online setzen (Router-Wahrheit
        // fuer WLAN-/LAN-Verbindung). Offline bleibt weiterhin Sache des
        // PresenceWorkers (TCP + Hysterese), damit ein einzelner FritzBox-
        // Zyklus kein Geraet faelschlich offline reisst.
        if(active) {
            d->lastSeen = bootSec;
            d->probeMiss = 0;
            if(!d->active) {
                d->active = true;
                d->onlineSince = bootSec;
                d->offlineSince = 0;
                d->changed = true;
                addEvent(EV_ONLINE, d->ip, d->mac);
            }
            ssePushDeviceUpdate(d->ip);
        }
    }

    frbLastCount = total;
    frbLastNew   = neu;
    // Diagnose-String (Review 9): itemsParsed/itemsNew + Auth-Status + Pfad
    frbStatus = String(total) + " Geraete geparst" + (neu>0 ? (", " + String(neu) + " neu") : "")
              + (frbLastAuthUsed ? (frbLastAuthOk ? ", Digest-Auth OK" : ", Digest-Auth fehlgeschlagen") : "");
    Serial.println("[FRB] " + frbStatus + " | path=" + frbLastPath + " | httpCode=" + String(frbLastHttpCode));
}


void saveDevice(Device* d) {
    if(!d->confirmed || d->lastSeen == 0) return; // nur bestaetigte Geraete
    prefs.begin("net", false);
    String key = String(d->ip); key.replace(".",""); key.replace(":","");
    if(key.length() > 14) key = key.substring(0,14);
    String val = String(d->ip)+"|"+String(d->mac)+"|"+String(d->vendor)+"|"+
                 String(d->label)+"|"+String(d->note)+"|"+
                 String(d->hostname)+"|"+String(d->dtype)+"|"+
                 String(d->active?1:0)+"|"+String(d->lastSeen)+"|"+
                 String(d->firstSeen)+"|"+String(d->onlineSince)+"|"+
                 String(d->offlineSince)+"|"+String(d->openPortBits)+"|"+
                 String(d->portsScanned?1:0)+"|"+String(d->lastSuccessPort);
    prefs.putString(key.c_str(), val);
    prefs.end();
    d->changed = false;
}

void flushDirtyDevices() {
    prefs.begin("net", false);
    for(int i=0;i<devCount;i++){
        if(!devs[i].changed) continue;
        if(!devs[i].confirmed || devs[i].lastSeen == 0) continue; // nur bestaetigte
        String key = String(devs[i].ip); key.replace(".",""); key.replace(":","");
        if(key.length() > 14) key = key.substring(0,14);
        Device& d = devs[i];
        String val = String(d.ip)+"|"+String(d.mac)+"|"+String(d.vendor)+"|"+
                     String(d.label)+"|"+String(d.note)+"|"+
                     String(d.hostname)+"|"+String(d.dtype)+"|"+
                     String(d.active?1:0)+"|"+String(d.lastSeen)+"|"+
                     String(d.firstSeen)+"|"+String(d.onlineSince)+"|"+
                     String(d.offlineSince)+"|"+String(d.openPortBits)+"|"+
                     String(d.portsScanned?1:0)+"|"+String(d.lastSuccessPort);
        prefs.putString(key.c_str(), val);
        devs[i].changed = false;
    }
    prefs.end();
}

void loadDevices() {
    String base;
    if(subnetBase.length()>0) { base=subnetBase; }
    else { IPAddress ip=WiFi.localIP(); base=String(ip[0])+"."+String(ip[1])+"."+String(ip[2]); }
    prefs.begin("net",true);
    for(int i=SCAN_START;i<=SCAN_END;i++){
        char ipBuf[16]; snprintf(ipBuf,16,"%s.%d",base.c_str(),i);
        String key=String(ipBuf); key.replace(".",""); key=key.substring(0,14);
        String val=prefs.getString(key.c_str(),"");
        if(val.length()<5) continue;
        String f[16]; int fi=0,p=0;
        for(int j=0;j<=(int)val.length()&&fi<16;j++){
            if(j==(int)val.length()||val[j]=='|'){f[fi++]=val.substring(p,j);p=j+1;}
        }
        if(fi<10) continue;
        // Nur laden wenn lastSeen > 0 (jemals wirklich online gewesen)
        unsigned long ls = fi>8 ? f[8].toInt() : 0;
        if(ls == 0) continue;
        Device* d=findOrCreate(ipBuf);
        if(!d) continue;
        strncpy(d->mac,    fi>1?f[1].c_str():"",17);
        strncpy(d->vendor, fi>2?f[2].c_str():"",23);
        strncpy(d->label,  fi>3?f[3].c_str():"",31);
        strncpy(d->note,   fi>4?f[4].c_str():"",63);
        strncpy(d->hostname,fi>5?f[5].c_str():"",47);
        d->dtype       = fi>6  ? f[6].toInt()  : 0;
        d->active      = false; // Neu pruefen
        d->lastSeen    = fi>8  ? f[8].toInt()  : 0;
        d->firstSeen   = fi>9  ? f[9].toInt()  : 0;
        d->onlineSince = fi>10 ? f[10].toInt() : 0;
        d->offlineSince= fi>11 ? f[11].toInt() : 0;
        d->openPortBits= fi>12 ? (uint32_t)f[12].toInt() : 0;
        d->portsScanned= fi>13 && f[13]=="1";
        d->lastSuccessPort = fi>14 ? (uint16_t)f[14].toInt() : 0;
        d->changed      = false;
        d->confirmed    = true;   // aus NVS = war schon bestaetigt
        d->probeSeen    = 0;
        d->probeMiss    = 0;
        d->enrichQueued = false;
    }
    prefs.end();
    Serial.printf("[NET] %d bestaetigte Geraete geladen\n", devCount);
}

void saveSettings() {
    prefs.begin("netcfg",false);
    prefs.putInt("timeout", scanTimeoutMs);
    prefs.putString("subnet", subnetBase);
    prefs.putBool("frbEn", frbEnabled);
    prefs.putString("frbHost", frbHost);
    prefs.putString("frbUser", frbUser);
    prefs.putString("frbPass", frbPass);
    prefs.putULong("frbIntvl", frbIntervalMs);
    prefs.end();
}
void loadSettings() {
    prefs.begin("netcfg",true);
    scanTimeoutMs = prefs.getInt("timeout", 200);
    subnetBase    = prefs.getString("subnet","");
    frbEnabled    = prefs.getBool("frbEn", false);
    frbHost       = prefs.getString("frbHost","");
    frbUser       = prefs.getString("frbUser","");
    frbPass       = prefs.getString("frbPass","");
    frbIntervalMs = prefs.getULong("frbIntvl", 300000UL);
    prefs.end();
}

// ================================================================
//  WORKER-MODELL (Discovery / Presence / Enrichment getrennt)
// ================================================================
//
// Architektur: pro loop()-Tick genau EINE kleine Aufgabe.
// Worker A: DiscoveryWorker - scannt unbekannte IPs (Fast-Probe)
// Worker B: PresenceWorker  - prueft bekannte Geraete auf Statuswechsel
// Worker C: EnrichmentWorker - holt MAC/Hostname fuer neue Treffer
//
// Kandidaten-Phase: unbekannte IP erst nach 2 Treffern als Geraet anlegen
// Hysterese: bekanntes Geraet erst nach OFFLINE_THRESHOLD Fehlversuchen offline

#define OFFLINE_THRESHOLD  3   // Fehlversuche bis Geraet als offline gilt
#define CONFIRM_THRESHOLD  2   // Treffer bis unbekannte IP als Geraet gilt

// Enrichment-Queue: IPs die MAC/Hostname-Lookup benoetigen
#define ENRICH_QUEUE_SIZE 8
static char enrichQueue[ENRICH_QUEUE_SIZE][16];
static int  enrichHead = 0;
static int  enrichTail = 0;

void enrichEnqueue(const char* ip) {
    // Doppelte Eintraege vermeiden
    for(int i = enrichTail; i != enrichHead; i = (i+1) % ENRICH_QUEUE_SIZE)
        if(strcmp(enrichQueue[i], ip) == 0) return;
    // Overflow-Schutz: Queue voll = aeltesten Eintrag ueberspringen (Ring-Semantik)
    int nextHead = (enrichHead + 1) % ENRICH_QUEUE_SIZE;
    if(nextHead == enrichTail) {
        // Queue voll: aeltesten Eintrag verwerfen (tail vorschieben)
        enrichTail = (enrichTail + 1) % ENRICH_QUEUE_SIZE;
    }
    strncpy(enrichQueue[enrichHead], ip, 15);
    enrichQueue[enrichHead][15] = 0;
    enrichHead = nextHead;
}

// ── Worker A: Discovery (unbekannte IPs, Fast-Probe) ─────────────
void discoveryWorker() {
    String base;
    if(subnetBase.length()>0){ base=subnetBase; }
    else { IPAddress myIp=WiFi.localIP(); base=String(myIp[0])+"."+String(myIp[1])+"."+String(myIp[2]); }

    char ip[16];
    snprintf(ip, 16, "%s.%d", base.c_str(), ringIp);
    unsigned long bootSec = millis()/1000UL;

    // Eigene IP: immer online markieren, kein Probe noetig
    if(String(ip) == getLocalIp()) {
        Device* d = findOrCreate(ip);
        if(d && !d->active) {
            d->active=true; d->lastSeen=bootSec; d->confirmed=true;
            if(d->firstSeen==0){ d->firstSeen=bootSec; d->onlineSince=bootSec; }
            if(strlen(d->hostname)==0) strncpy(d->hostname, deviceName.c_str(), 47);
            if(d->dtype==0) d->dtype=3;
            d->changed=true;
        }
        ringIp = (ringIp >= SCAN_END) ? SCAN_START : ringIp + 1;
        return;
    }

    // Bekannte (confirmed) Geraete werden vom PresenceWorker behandelt
    Device* existing = nullptr;
    for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0){ existing=&devs[i];break; }
    if(existing && existing->confirmed) {
        ringIp = (ringIp >= SCAN_END) ? SCAN_START : ringIp + 1;
        return; // PresenceWorker ist zustaendig
    }

    // Unbekannte IP: Fast-Probe
    unsigned long t0 = millis();
    uint16_t hitPort = 0;
    bool alive = isOnlinePort(ip, &hitPort);
    unsigned long ms = millis() - t0;

    // Ring-Log aktualisieren (nur Treffer)
    if(alive) {
        RingLogEntry& le = ringLog[ringLogHead % RING_LOG_SIZE];
        strncpy(le.ip, ip, 15); le.found=true; le.ms=ms;
        strncpy(le.info, "neu?", 23);
        ringLogHead++;
    }

    if(alive) {
        // Kandidat anlegen oder Treffer zaehlen
        if(!existing) {
            // Neues Device nur als Kandidat (confirmed=false)
            existing = findOrCreate(ip);
            if(existing) {
                existing->confirmed = false;
                existing->probeSeen = 1;
                existing->probeMiss = 0;
                existing->lastSeen  = bootSec;
                if(hitPort) existing->lastSuccessPort = hitPort;
                if(existing->firstSeen==0) existing->firstSeen=bootSec;
            }
        } else {
            // Bestehender Kandidat: Treffer zaehlen
            existing->probeSeen++;
            existing->probeMiss = 0;
            existing->lastSeen  = bootSec;
            if(hitPort) existing->lastSuccessPort = hitPort;
            // Nach CONFIRM_THRESHOLD Treffern: bestaetigen und Event ausloesen
            if(!existing->confirmed && existing->probeSeen >= CONFIRM_THRESHOLD) {
                existing->confirmed  = true;
                existing->active     = true;
                existing->onlineSince= bootSec;
                existing->offlineSince=0;
                existing->changed    = true;
                addEvent(EV_NEW, ip, "");
                enrichEnqueue(ip); // MAC + Hostname nachholen
                ssePushDeviceUpdate(ip);
            }
        }
    } else {
        // Kein Treffer: Kandidaten nicht sofort loeschen, nur Fehlversuch zaehlen
        if(existing && !existing->confirmed) {
            existing->probeMiss++;
            if(existing->probeMiss >= 3) {
                // Kandidat verwirft sich selbst - Geraet nie wirklich gesehen
                // Aus Array entfernen
                int idx = existing - devs;
                for(int i=idx;i<devCount-1;i++) devs[i]=devs[i+1];
                devCount--;
            }
        }
    }

    ringIp = (ringIp >= SCAN_END) ? SCAN_START : ringIp + 1;
    ringScanCount++;
}

// ── Worker B: Presence (bekannte/confirmed Geraete) ───────────────
// Wird abwechselnd mit discoveryWorker aufgerufen
static int presenceIdx = 0;

void presenceWorker() {
    // Kein confirmed Geraet vorhanden
    int confirmed = 0;
    for(int i=0;i<devCount;i++) if(devs[i].confirmed) confirmed++;
    if(confirmed == 0) return;

    // Infrastruktur-Priorisierung: Router (.1), bekannte Repeater/Server
    // werden bevorzugt geprueft, damit der Online-Status schnell aktuell ist.
    // Strategie: jeder 4. Presence-Tick prueft explizit die niedrigste aktive IP.
    static uint8_t infraCounter = 0;
    infraCounter++;
    if(infraCounter >= 4) {
        infraCounter = 0;
        // Ersten confirmed Eintrag mit niedrigster IP pruefen
        Device* infra = nullptr;
        for(int i=0;i<devCount;i++) {
            if(!devs[i].confirmed) continue;
            if(!infra || atoi(strrchr(devs[i].ip,'.')+1) < atoi(strrchr(infra->ip,'.')+1))
                infra = &devs[i];
        }
        if(infra) {
            // Presence-Check fuer Infrastruktur-Geraet
            unsigned long bootSec = millis()/1000UL;
            bool alive = isOnlinePreferred(infra);
            if(alive) {
                infra->probeMiss = 0; infra->lastSeen = bootSec;
                if(!infra->active) {
                    infra->active=true; infra->onlineSince=bootSec; infra->offlineSince=0;
                    infra->changed=true; addEvent(EV_ONLINE, infra->ip, infra->mac);
                    ssePushDeviceUpdate(infra->ip);
                }
            } else {
                infra->probeMiss++;
                if(infra->active && infra->probeMiss >= OFFLINE_THRESHOLD) {
                    infra->active=false; infra->offlineSince=bootSec; infra->onlineSince=0;
                    infra->changed=true; addEvent(EV_OFFLINE, infra->ip, infra->mac);
                    ssePushDeviceUpdate(infra->ip);
                }
            }
            return;
        }
    }

    // Naechstes confirmed Geraet finden (round-robin)
    int checked = 0;
    while(checked < devCount) {
        presenceIdx = presenceIdx % devCount;
        Device& d = devs[presenceIdx];
        presenceIdx++;
        checked++;
        if(!d.confirmed) continue;

        unsigned long bootSec = millis()/1000UL;
        bool alive = isOnlinePreferred(&d);

        // Ring-Log
        {
            RingLogEntry& le = ringLog[ringLogHead % RING_LOG_SIZE];
            strncpy(le.ip, d.ip, 15); le.found=alive; le.ms=0;
            strncpy(le.info, alive ? (strlen(d.hostname)>0?d.hostname:"online") : "miss", 23);
            ringLogHead++;
        }

        if(alive) {
            d.probeMiss = 0;
            d.lastSeen  = bootSec;
            if(!d.active) {
                // War offline, jetzt wieder online
                d.active      = true;
                d.onlineSince = bootSec;
                d.offlineSince= 0;
                d.changed     = true;
                addEvent(EV_ONLINE, d.ip, d.mac);
                ssePushDeviceUpdate(d.ip);
            }
        } else {
            d.probeMiss++;
            if(d.active && d.probeMiss >= OFFLINE_THRESHOLD) {
                // Erst nach N Fehlversuchen offline schalten (Hysterese)
                d.active       = false;
                d.offlineSince = bootSec;
                d.onlineSince  = 0;
                d.changed      = true;
                addEvent(EV_OFFLINE, d.ip, d.mac);
                ssePushDeviceUpdate(d.ip);
            }
        }
        return; // Pro Tick nur EIN Geraet pruefen
    }
}

// ── Worker C: Enrichment (MAC + Hostname nach Bestätigung) ────────
void enrichmentWorker() {
    if(enrichHead == enrichTail) return; // Queue leer

    char ip[16];
    strncpy(ip, enrichQueue[enrichTail], 15);
    enrichTail = (enrichTail + 1) % ENRICH_QUEUE_SIZE;

    Device* d = nullptr;
    for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0){d=&devs[i];break;}
    if(!d || !d->confirmed) return;

    tryGetMac(ip, d);
    // Nach MAC-Ermittlung pruefen ob dieses Geraet schon unter anderer IP bekannt ist
    mergeByMac(ip, d);
    if(strlen(d->hostname)==0) tryGetHostname(ip, d);
    if(d->dtype==0) inferDtype(d);
    d->changed = true;
    ssePushDeviceUpdate(ip);
}

// ── Haupt-Scheduler: wechselt zwischen Workern ────────────────────
// Verhältnis: 2x Discovery, 1x Presence, 1x Enrichment
static uint8_t schedPhase = 0;

void doRingTick() {
    if(!ringRunning) return;
    schedPhase = (schedPhase + 1) % 4;
    if(schedPhase == 3) {
        enrichmentWorker();
    } else if(schedPhase == 2) {
        presenceWorker();
    } else {
        discoveryWorker();
    }
}

// ================================================================
//  PING + PORTSCAN
// ================================================================
String doPing(const char* ip) {
    int ok=0; unsigned long mn=99999,mx=0,sm=0;
    for(int i=0;i<3;i++){
        unsigned long t=millis(); bool conn=false;
        for(int pi=0;pi<SCAN_PORT_COUNT&&!conn;pi++)
            conn=tcpProbe(ip,SCAN_PORTS[pi],800);
        if(conn){ unsigned long rtt=millis()-t; ok++; sm+=rtt; if(rtt<mn)mn=rtt; if(rtt>mx)mx=rtt; }
    }
    int loss=100-(ok*33);
    String r="{\"ok\":"+String(ok)+",\"loss\":"+String(loss);
    if(ok>0) r+=",\"min\":"+String(mn)+",\"avg\":"+String(sm/ok)+",\"max\":"+String(mx);
    return r+"}";
}

String doPortScan(const char* ip) {
    uint32_t bits=0;
    for(int i=0;i<PORT_LIST_CNT;i++){
        if(tcpProbe(ip,PORT_LIST[i],400)) bits|=(1UL<<i);
        webServer.handleClient();
        yield();
    }
    Device* d=nullptr; for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0){d=&devs[i];break;}
    if(d){
        d->openPortBits=bits; d->portsScanned=true; d->changed=true; inferDtype(d);
        // Pflichtfix: ein gefundener offener Port bedeutet das Geraet ist
        // JETZT erreichbar - die Hauptliste muss das sofort widerspiegeln,
        // sonst zeigt die UI "offline" obwohl der Portscan einen Treffer hatte.
        if(bits != 0) {
            unsigned long bootSec = millis()/1000UL;
            bool wasOff = !d->active;
            d->probeMiss = 0;
            d->lastSeen  = bootSec;
            // Ersten Treffer-Port als bevorzugten Presence-Port merken
            for(int i=0;i<PORT_LIST_CNT;i++){
                if((bits>>i)&1){ d->lastSuccessPort = PORT_LIST[i]; break; }
            }
            if(!d->confirmed){
                d->confirmed   = true;
                if(d->firstSeen==0) d->firstSeen=bootSec;
                addEvent(EV_NEW, ip, "");
                enrichEnqueue(ip);
            }
            if(wasOff){
                d->active      = true;
                d->onlineSince = bootSec;
                d->offlineSince= 0;
                addEvent(EV_ONLINE, ip, d->mac);
            }
            ssePushDeviceUpdate(ip);
        }
    }
    String r="{\"ip\":\""+String(ip)+"\",\"ports\":[";
    bool first=true;
    for(int i=0;i<PORT_LIST_CNT;i++){
        if((bits>>i)&1){ if(!first)r+=","; r+=String(PORT_LIST[i]); first=false; }
    }
    return r+"]}";
}

// ================================================================
//  JSON BUILDER
// ================================================================
String buildDevicesJson(bool onlyOnline) {
    // Sortierung: aktive zuerst (nach IP aufsteigend), dann inaktive
    int idx[MAX_DEVICES]; int cnt=0;
    for(int i=0;i<devCount;i++){
        if(onlyOnline && !devs[i].active) continue;
        idx[cnt++]=i;
    }
    // Bubble sort: aktiv vor inaktiv, dann IP aufsteigend
    for(int i=0;i<cnt-1;i++) for(int j=i+1;j<cnt;j++){
        Device& a=devs[idx[i]]; Device& b=devs[idx[j]];
        bool sw=false;
        if(!a.active&&b.active) sw=true;
        else if(a.active==b.active){
            int ia=atoi(strrchr(a.ip,'.')+1), ib=atoi(strrchr(b.ip,'.')+1);
            if(ia>ib) sw=true;
        }
        if(sw){int t=idx[i];idx[i]=idx[j];idx[j]=t;}
    }
    String j="[";
    for(int n=0;n<cnt;n++){
        Device& d=devs[idx[n]];
        if(n>0) j+=",";
        j+="{\"ip\":\""+escJ(d.ip)+"\","
           "\"mac\":\""+escJ(d.mac)+"\","
           "\"vendor\":\""+escJ(d.vendor)+"\","
           "\"label\":\""+escJ(d.label)+"\","
           "\"note\":\""+escJ(d.note)+"\","
           "\"hn\":\""+escJ(strlen(d.hostname)>0?d.hostname:"-")+"\","
           "\"dtype\":"+String(d.dtype)+","
           "\"active\":"+String(d.active?"true":"false")+","
           "\"onlineSince\":\""+fmtTime(d.onlineSince)+"\","
           "\"offlineSince\":\""+fmtTime(d.offlineSince)+"\","
           "\"firstSeen\":\""+fmtTime(d.firstSeen)+"\","
           "\"lastSeen\":\""+fmtTime(d.lastSeen)+"\","
           "\"portBits\":"+String(d.openPortBits)+","
           "\"portsScanned\":"+String(d.portsScanned?"true":"false")+"}";
    }
    return j+"]";
}


// ================================================================
//  API HANDLER
// ================================================================
void handleApiSse() {
    sseAlive=false; sseCli.stop();
    sseCli=webServer.client(); sseAlive=true;
    webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
    webServer.sendHeader("Content-Type","text/event-stream");
    webServer.sendHeader("Cache-Control","no-cache");
    webServer.sendHeader("Connection","keep-alive");
    webServer.send(200);
    sseCli.print("data:connected\n\n");
}

void handleApiDevices() {
    bool onlyOnline = webServer.hasArg("online") && webServer.arg("online")=="1";
    webServer.send(200,"application/json",buildDevicesJson(onlyOnline));
}

void handleApiSave() {
    if(!webServer.hasArg("plain")){ webServer.send(400,"application/json","{\"ok\":false}"); return; }
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(512);
    #endif
    deserializeJson(doc,webServer.arg("plain"));
    const char* ip=doc["ip"]|"";
    Device* d=nullptr; for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0){d=&devs[i];break;}
    if(!d){ webServer.send(404,"application/json","{\"ok\":false}"); return; }
    if(doc.containsKey("label"))  strncpy(d->label,  doc["label"].as<String>().c_str(), 31);
    if(doc.containsKey("note"))   strncpy(d->note,   doc["note"].as<String>().c_str(),  63);
    if(doc.containsKey("dtype"))  d->dtype=(uint8_t)(int)doc["dtype"];
    d->changed=true;
    saveDevice(d);
    webServer.send(200,"application/json","{\"ok\":true}");
}

void handleApiDelete() {
    if(!webServer.hasArg("plain")){ webServer.send(400,"application/json","{\"ok\":false}"); return; }
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(128);
    #endif
    deserializeJson(doc,webServer.arg("plain"));
    const char* ip=doc["ip"]|"";
    int idx=-1; for(int i=0;i<devCount;i++) if(strcmp(devs[i].ip,ip)==0){idx=i;break;}
    if(idx<0){ webServer.send(404,"application/json","{\"ok\":false}"); return; }
    // NVS-Key loeschen
    prefs.begin("net",false);
    String key=String(ip); key.replace(".",""); key.replace(":","");
    if(key.length()>14) key=key.substring(0,14);
    prefs.remove(key.c_str());
    prefs.end();
    for(int i=idx;i<devCount-1;i++) devs[i]=devs[i+1];
    devCount--;
    webServer.send(200,"application/json","{\"ok\":true}");
}

void handleApiPing() {
    if(!webServer.hasArg("plain")){ webServer.send(400,"application/json","{\"ok\":false}"); return; }
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(128);
    #endif
    deserializeJson(doc,webServer.arg("plain"));
    String ip=doc["ip"].as<String>();
    webServer.send(200,"application/json",doPing(ip.c_str()));
}

void handleApiPortScan() {
    if(!webServer.hasArg("plain")){ webServer.send(400,"application/json","{\"ok\":false}"); return; }
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(128);
    #endif
    deserializeJson(doc,webServer.arg("plain"));
    String ip=doc["ip"].as<String>();
    webServer.send(200,"application/json",doPortScan(ip.c_str()));
}

void handleApiSettings() {
    if(webServer.method()==HTTP_GET){
        String j="{\"timeout\":"+String(scanTimeoutMs)+",\"subnet\":\""+subnetBase+"\","
                 "\"frbEnabled\":"+String(frbEnabled?"true":"false")+","
                 "\"frbHost\":\""+frbHost+"\","
                 "\"frbUser\":\""+escJ(frbUser.c_str())+"\","
                 "\"frbHasPass\":"+String(frbPass.length()>0?"true":"false")+","
                 "\"frbInterval\":"+String(frbIntervalMs/1000UL)+","
                 "\"frbStatus\":\""+escJ(frbStatus.c_str())+"\","
                 "\"frbCount\":"+String(frbLastCount)+","
                 "\"frbHttpCode\":"+String(frbLastHttpCode)+","
                 "\"frbAuthUsed\":"+String(frbLastAuthUsed?"true":"false")+","
                 "\"frbAuthOk\":"+String(frbLastAuthOk?"true":"false")+","
                 "\"frbPath\":\""+escJ(frbLastPath.c_str())+"\"}";
        webServer.send(200,"application/json",j); return;
    }
    if(!webServer.hasArg("plain")){ webServer.send(400,"application/json","{\"ok\":false}"); return; }
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(256);
    #endif
    deserializeJson(doc,webServer.arg("plain"));
    if(doc.containsKey("timeout")) scanTimeoutMs=(int)doc["timeout"];
    if(doc.containsKey("subnet"))  subnetBase=doc["subnet"].as<String>();
    if(doc.containsKey("frbEnabled")) frbEnabled=doc["frbEnabled"].as<bool>();
    if(doc.containsKey("frbHost"))    frbHost=doc["frbHost"].as<String>();
    if(doc.containsKey("frbUser"))    frbUser=doc["frbUser"].as<String>();
    // Passwort nur ueberschreiben wenn explizit (nicht-leer) gesendet -
    // die UI sendet beim Laden kein Passwort zurueck (frbHasPass-Flag).
    if(doc.containsKey("frbPass") && doc["frbPass"].as<String>().length()>0)
        frbPass=doc["frbPass"].as<String>();
    if(doc.containsKey("frbInterval")) {
        long iv = (long)doc["frbInterval"];
        if(iv < 30) iv = 30; // Mindestabstand 30s
        frbIntervalMs = (unsigned long)iv * 1000UL;
    }
    saveSettings();
    webServer.send(200,"application/json","{\"ok\":true}");
}

// Loest sofort einen FritzBox-Pull aus (Settings-Tab "Jetzt abrufen").
// Blockiert kurz (HTTP-Requests, ca. 1-2s) - vertretbar fuer einen
// manuell ausgeloesten Button-Klick.
void handleApiFritzboxNow() {
    if(!frbEnabled) { webServer.send(400,"application/json","{\"ok\":false,\"error\":\"disabled\"}"); return; }
    fritzboxPoll();
    lastFrbPoll = millis();
    String j = "{\"ok\":true,\"status\":\""+escJ(frbStatus.c_str())+"\",\"count\":"+String(frbLastCount)+"}";
    webServer.send(200,"application/json",j);
}

void handleApiStatus() {
    unsigned long up=millis()/1000UL;
    int active=0; for(int i=0;i<devCount;i++) if(devs[i].active) active++;
    String j="{";
    j += "\"name\":\""+escJ(deviceName.c_str())+"\"";
    j += ",\"version\":\"" FW_VERSION "\"";
    j += ",\"chip\":\""+escJ(hwInfo.chipModel().c_str())+"\"";
    j += ",\"mac\":\""+getMac()+"\"";
    j += ",\"ip\":\""+getLocalIp()+"\"";
    j += ",\"rssi\":"+String(WiFi.RSSI());
    j += ",\"uptime\":"+String(up);
    j += ",\"heap\":"+String(hwInfo.freeHeap());
    j += ",\"freeHeap\":"+String(hwInfo.freeHeap());
    j += ",\"psram\":"+String(hwInfo.freePsram());
    j += ",\"psramSize\":"+String(hwInfo.psramSize());
    j += ",\"sketch\":"+String(hwInfo.freeSketchSpace());
    j += ",\"hub\":\""+hubHost+":"+String(hubPort)+"\"";
    j += ",\"interval\":"+String(heartbeatInterval/1000UL);
    j += ",\"subnet\":\""+subnetBase+"\"";
    j += ",\"devices\":"+String(devCount);
    j += ",\"online\":"+String(active);
    j += ",\"ringIp\":"+String(ringIp);
    j += ",\"timeout\":"+String(scanTimeoutMs);
    hwInfo.appendStatusFields(j);
    CpuLoad::appendStatusFields(j);
    j += ",\"rlog\":["+buildRingLog()+"]}";
    webServer.send(200,"application/json",j);
}

void handleApiEvents() {
    webServer.send(200,"application/json",buildEventsJson());
}

// Baut JSON-Array der letzten Ring-Scan-Eintraege fuer Tab-1-Mini-Log
String buildRingLog() {
    int cnt = min(ringLogHead, RING_LOG_SIZE);
    String j = "";
    for(int i = 0; i < cnt; i++) {
        int idx = ((ringLogHead - 1 - i) + RING_LOG_SIZE) % RING_LOG_SIZE;
        RingLogEntry& e = ringLog[idx];
        if(i > 0) j += ",";
        j += String("{\"ip\":\"") + escJ(e.ip) + "\","
           + "\"ok\":"  + String(e.found ? "true" : "false") + ","
           + "\"ms\":"  + String(e.ms) + ","
           + "\"info\":\"" + escJ(e.info) + "\"}";
    }
    return j;
}

// ================================================================
//  WEB UI (handleRoot)
// ================================================================
void handleRoot() {
    webServer.sendHeader(F("Content-Encoding"), F("gzip"));
    webServer.sendHeader(F("Cache-Control"), F("no-store"));
    webServer.send_P(200, "text/html", (PGM_P)PAGE_MAIN_GZ, PAGE_MAIN_GZ_LEN);
}

void handleOtaPage() {
    webServer.sendHeader(F("Content-Encoding"), F("gzip"));
    webServer.sendHeader(F("Cache-Control"), F("no-store"));
    webServer.send_P(200, "text/html", (PGM_P)PAGE_OTA_GZ, PAGE_OTA_GZ_LEN);
}

void handleOtaUpload() {
    HTTPUpload& u=webServer.upload();
    if(u.status==UPLOAD_FILE_START){if(!Update.begin(UPDATE_SIZE_UNKNOWN))Update.printError(Serial);}
    else if(u.status==UPLOAD_FILE_WRITE){if(Update.write(u.buf,u.currentSize)!=u.currentSize)Update.printError(Serial);}
    else if(u.status==UPLOAD_FILE_END){if(Update.end(true))Serial.printf("[OTA] OK %u bytes\n",u.totalSize);}
}
void handleOtaUploadFinish() {
    if(Update.hasError()) webServer.send(500,"text/plain","OTA failed");
    else                  webServer.send(200,"text/plain","OK");
    delay(500); ESP.restart();
}
void handleNotFound() { webServer.sendHeader("Location","/",true); webServer.send(302,"text/plain",""); }

// ================================================================
//  WEB SERVER SETUP
// ================================================================
void setupWebServer() {
    webServer.on("/",              HTTP_GET,  handleRoot);
    webServer.on("/ota",           HTTP_GET,  handleOtaPage);
    webServer.on("/ota-upload",    HTTP_POST, handleOtaUploadFinish, handleOtaUpload);
    webServer.on("/api/sse",       HTTP_GET,  handleApiSse);
    webServer.on("/api/devices",   HTTP_GET,  handleApiDevices);
    webServer.on("/api/save",      HTTP_POST, handleApiSave);
    webServer.on("/api/delete",    HTTP_POST, handleApiDelete);
    webServer.on("/api/ping",      HTTP_POST, handleApiPing);
    webServer.on("/api/portscan",  HTTP_POST, handleApiPortScan);
    webServer.on("/api/settings",  HTTP_GET,  handleApiSettings);
    webServer.on("/api/settings",  HTTP_POST, handleApiSettings);
    webServer.on("/api/fritzbox-now", HTTP_POST, handleApiFritzboxNow);
    webServer.on("/api/status",    HTTP_GET,  handleApiStatus);
    webServer.on("/api/events",    HTTP_GET,  handleApiEvents);
    webServer.onNotFound(handleNotFound);
    webServer.begin();
    Serial.println("[WEB] http://"+getLocalIp()+"/");
}

// ================================================================
//  RESET-TASTE
// ================================================================
void checkResetButton() {
    #if RESET_BUTTON_PIN == 255
    return; // Reset-Taste deaktiviert
    #else
    pinMode(RESET_BUTTON_PIN, INPUT_PULLUP);
    if(digitalRead(RESET_BUTTON_PIN)==HIGH) return;
    unsigned long start=millis();
    while(digitalRead(RESET_BUTTON_PIN)==LOW){
        if(millis()-start>(unsigned long)RESET_HOLD_SEC*1000UL){
            wifiManager.resetSettings();
            prefs.begin("net",false); prefs.clear(); prefs.end();
            prefs.begin("netcfg",false); prefs.clear(); prefs.end();
            prefs.begin("esphub",false); prefs.clear(); prefs.end();
            delay(500); ESP.restart();
        }
        delay(100);
    }
    #endif
}

// ================================================================
//  WIFI SETUP
// ================================================================
void setupWifi() {
    prefs.begin("esphub",false);
    String sn=prefs.getString("name",    deviceName);
    String sh=prefs.getString("hub_host",hubHost);
    int    sp=prefs.getInt   ("hub_port",hubPort);
    prefs.end();
    deviceName=sn; hubHost=sh; hubPort=sp;

    WiFiManagerParameter pN("name",     "Geraetename",  deviceName.c_str(), 32);
    WiFiManagerParameter pH("hub_host", "ESP-Hub IP",   hubHost.c_str(),    40);
    WiFiManagerParameter pP("hub_port", "ESP-Hub Port", String(hubPort).c_str(), 6);
    wifiManager.addParameter(&pN);
    wifiManager.addParameter(&pH);
    wifiManager.addParameter(&pP);
    wifiManager.setConfigPortalTimeout(WIFI_PORTAL_TIMEOUT_S);
    wifiManager.setAPCallback([](WiFiManager*m){ Serial.println("[WiFi] Portal: " WIFI_AP_NAME); });
    if(!wifiManager.autoConnect(WIFI_AP_NAME)){ delay(1000); ESP.restart(); }

    prefs.begin("esphub",false);
    prefs.putString("name",    String(pN.getValue()));
    prefs.putString("hub_host",String(pH.getValue()));
    prefs.putInt   ("hub_port",String(pP.getValue()).toInt());
    prefs.end();
    deviceName=String(pN.getValue());
    hubHost   =String(pH.getValue());
    hubPort   =String(pP.getValue()).toInt();
    Serial.println("[WiFi] "+getLocalIp()+" | "+deviceName);
}

// ================================================================
//  HEARTBEAT
// ================================================================
String buildHeartbeat() {
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(512);
    #endif
    doc["mac"]        = getMac();
    doc["name"]       = deviceName;
    doc["hwType"]     = "esp32";
    doc["chipModel"]  = hwInfo.chipModel();
    doc["version"]    = FW_VERSION;
    doc["ip"]         = getLocalIp();
    doc["rssi"]       = WiFi.RSSI();
    doc["uptime"]     = millis()/1000UL;
    doc["freeHeap"]   = hwInfo.freeHeap();
    doc["freeSketch"] = hwInfo.freeSketchSpace();
    doc["hwSummary"]  = hwInfo.summaryLine();
    doc["module"]     = hwInfo.moduleGuess();
    {
        const int c0 = CpuLoad::core0Percent();
        const int c1 = CpuLoad::core1Percent();
        doc["cpu"] = (c1 >= 0) ? ((c0 + c1) / 2) : c0;
    }
    int active=0; for(int i=0;i<devCount;i++) if(devs[i].active) active++;
    #if ARDUINOJSON_VERSION_MAJOR>=7
      JsonObject ios=doc["ios"].to<JsonObject>();
      JsonObject d1=ios["devices"].to<JsonObject>(); d1["type"]="sensor";d1["value"]=devCount;d1["unit"]="";
      JsonObject d2=ios["online"].to<JsonObject>();  d2["type"]="sensor";d2["value"]=active; d2["unit"]="";
    #else
      JsonObject ios=doc.createNestedObject("ios");
      JsonObject d1=ios.createNestedObject("devices"); d1["type"]="sensor";d1["value"]=devCount;d1["unit"]="";
      JsonObject d2=ios.createNestedObject("online");  d2["type"]="sensor";d2["value"]=active; d2["unit"]="";
    #endif
    String out; serializeJson(doc,out); return out;
}

void sendHeartbeat() {
    if(WiFi.status()!=WL_CONNECTED) return;
    HTTPClient http;
    http.begin("http://"+hubHost+":"+String(hubPort)+"/api/register");
    http.addHeader("Content-Type","application/json");
    http.setTimeout(5000);
    int code=http.POST(buildHeartbeat());
    if(code==200){
        #if ARDUINOJSON_VERSION_MAJOR>=7
          JsonDocument resp;
        #else
          DynamicJsonDocument resp(256);
        #endif
        if(deserializeJson(resp,http.getString())==DeserializationError::Ok){
            if(resp.containsKey("interval")){
                unsigned long ni=(unsigned long)(int)resp["interval"]*1000UL;
                if(ni>=5000UL) heartbeatInterval=ni;
            }
            if(resp.containsKey("otaUrl")&&!resp["otaUrl"].isNull()){
                String u=resp["otaUrl"].as<String>();
                if(u.length()>0){ otaPending=true; otaUrl=u; }
            }
            if(resp.containsKey("name")&&!resp["name"].isNull()){
                String newName=resp["name"].as<String>();
                newName.trim();
                if(newName.length()>0&&newName!=deviceName){
                    deviceName=newName;
                    prefs.begin("esphub",false); prefs.putString("name",deviceName); prefs.end();
                    Serial.println("[HB] Name: "+deviceName);
                }
            }
        }
    }
    http.end();
}

void performOta(const String& url) {
    HTTPClient http; http.begin(url); http.setTimeout(30000);
    int code=http.GET(); if(code!=200){http.end();return;}
    int len=http.getSize();
    if(!Update.begin(len>0?len:UPDATE_SIZE_UNKNOWN)){http.end();return;}
    WiFiClient* s=http.getStreamPtr();
    uint8_t buf[512]; size_t w=0;
    while(http.connected()&&(len<=0||w<(size_t)len)){
        size_t av=s->available(); if(!av){delay(1);continue;}
        size_t r=s->readBytes(buf,min(av,sizeof(buf))); if(!r)break;
        Update.write(buf,r); w+=r;
    }
    if(Update.end(true)){http.end();delay(500);ESP.restart();}
    http.end();
}

// ================================================================
//  SETUP & LOOP
// ================================================================
// Liefert die letzte Reset-Ursache als lesbaren String.
// Hilft bei der Diagnose periodischer Reboots (Watchdog vs. Crash vs. Brownout).
String resetReasonStr() {
    switch(esp_reset_reason()) {
        case ESP_RST_POWERON:   return "Power-On";
        case ESP_RST_EXT:       return "External Pin";
        case ESP_RST_SW:        return "Software (ESP.restart)";
        case ESP_RST_PANIC:     return "Panic/Exception";
        case ESP_RST_INT_WDT:   return "Interrupt Watchdog";
        case ESP_RST_TASK_WDT:  return "Task Watchdog (TWDT)";
        case ESP_RST_WDT:       return "Other Watchdog";
        case ESP_RST_DEEPSLEEP: return "Deep Sleep Wake";
        case ESP_RST_BROWNOUT:  return "Brownout";
        case ESP_RST_SDIO:      return "SDIO";
        default:                return "Unknown";
    }
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== ESP Network Scanner v" FW_VERSION " ===");
    Serial.println("[BOOT] Reset-Reason: " + resetReasonStr());
    hwInfo.probe();
    hwInfo.logToSerial();
    CpuLoad::begin();
    checkResetButton();
    loadSettings();
    setupWifi();
    // NTP-Sync fuer echte Zeitstempel im Event-Log (v1.6.3).
    // Deutsche Zeitzone inkl. Sommerzeit-Regel (CET/CEST).
    // Nicht blockierend: time(nullptr) liefert bis zum ersten Sync ~0,
    // addEvent() speichert dann einen kleinen Epoch-Wert (1970) -
    // unkritisch, nur fuer die ersten paar Sekunden nach dem Boot.
    configTzTime("CET-1CEST,M3.5.0,M10.5.0/3", "pool.ntp.org", "time.nist.gov");
    // Subnetz aus WiFi ableiten falls leer
    if(subnetBase.length()==0){
        IPAddress ip=WiFi.localIP();
        subnetBase=String(ip[0])+"."+String(ip[1])+"."+String(ip[2]);
    }
    loadDevices();
    String mn=toMdnsName(deviceName);
    if(MDNS.begin(mn.c_str())){ MDNS.addService("http","tcp",80); Serial.println("[mDNS] "+mn+".local"); }
    setupWebServer();
    WiFi.setHostname(mn.c_str());
    sendHeartbeat();
    lastHeartbeat=millis();
    // NVS-Flush zeitlich von Heartbeat entkoppeln: beide laufen alle 30s,
    // ohne Offset wuerden HTTP-POST + Preferences-I/O regelmaessig
    // zusammenfallen (Lastspitze, moeglicher 30s-Reboot-Verdacht).
    // Offset von 15s sorgt dafuer, dass Flush mittig zwischen zwei
    // Heartbeats laeuft (15s, 45s, 75s ... vs. Heartbeat 30s, 60s, 90s).
    lastNvsSave = millis() - 15000UL;
    Serial.printf("[NET] %d Geraete geladen, Ring-Scan .%d-.%d\n", devCount, SCAN_START, SCAN_END);
}

void loop() {
    webServer.handleClient();
    CpuLoad::poll();
    unsigned long now=millis();

    // Ring-Scan: 1 IP pro Tick, Abstand mind. 50ms.
    // Bei 13 Ports x 200ms Worst-Case + 50ms Abstand: ~2,6s pro inaktiver IP.
    // Kompletter Durchlauf (254 IPs): variiert je nach Anzahl aktiver Geraete.
    // Die UI bleibt durch den kurzen Tick jederzeit responsiv.
    if(now-lastRingTick >= 50UL){
        lastRingTick=now;
        doRingTick();
    }

    // Heartbeat
    if(now-lastHeartbeat>=heartbeatInterval){ lastHeartbeat=now; sendHeartbeat(); }

    // OTA
    if(otaPending){ otaPending=false; performOta(otaUrl); otaUrl=""; }

    // Kein Heartbeat-Watchdog: Hub-Erreichbarkeit darf nie einen Reboot
    // ausloesen (analog io-control v1.2.1). sendHeartbeat() ist rein
    // best-effort; Updates laufen weiterhin ueber den Hub-Push (otaUrl).

    // NVS alle 30s flushen (nur geaenderte Eintraege = dirty-Flag).
    // 30s Puffer reduziert Flash-Schreibzyklen deutlich gegenueber
    // sofortigem Speichern nach jeder IP (frueheres Verhalten v1.2).
    if(now-lastNvsSave>=30000UL){ lastNvsSave=now; flushDirtyDevices(); }

    // FritzBox-Inventar periodisch pullen (best-effort, optional).
    // Blockiert kurz (HTTP); laeuft daher nur alle frbIntervalMs (Default 5min).
    if(frbEnabled && WiFi.status()==WL_CONNECTED && (now-lastFrbPoll>=frbIntervalMs)){
        lastFrbPoll=now;
        fritzboxPoll();
    }

    // SSE Keepalive alle 5s
    static unsigned long lastKa=0;
    if(now-lastKa>=5000UL){ lastKa=now; ssePush("ping","{}"); }

    // WiFi-Reconnect
    // Non-blocking WiFi-Reconnect: kein delay() in loop()!
    // delay(5000) wuerde WebServer und Ring-Scan fuer 5s blockieren.
    static unsigned long lastReconnectAttempt = 0;
    if(WiFi.status() != WL_CONNECTED) {
        if(now - lastReconnectAttempt > 5000UL) {
            lastReconnectAttempt = now;
            WiFi.reconnect();
        }
    }
}
