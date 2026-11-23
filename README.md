# Specter32

**A self-contained ESP32 WiFi security auditor with a browser UI.**

Specter32 turns a single ESP32 board into a wireless assessment tool: scan nearby
networks, discover clients, capture WPA handshakes and PMKIDs, run beacon and
deauthentication tests, and review the results from any phone or laptop — no
companion app or PC required.

[![Build Specter32 Firmware](https://github.com/mamun0xf/specter32/actions/workflows/build.yml/badge.svg)](https://github.com/mamun0xf/specter32/actions/workflows/build.yml)

> ### Authorized use only
> Specter32 transmits raw 802.11 frames, including deauthentication and beacon
> frames, and can impersonate a network's SSID. In most countries that is only
> legal against networks you own or have **explicit written permission** to test.
> Using it against third-party networks can be a criminal offence. You are
> responsible for how you use it.

---

## Contents

- [Features](#features)
- [Hardware](#hardware)
- [Requirements](#requirements)
- [Build and flash](#build-and-flash)
- [First boot](#first-boot)
- [Web interface](#web-interface)
- [HTTP API](#http-api)
- [Captures and files](#captures-and-files)
- [Project layout](#project-layout)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Author](#author)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| **Network scan** | SSID, BSSID, RSSI, channel, and security mode of nearby APs. Pick one as the target. |
| **Client discovery** | Passive scan for stations associated with the selected target BSSID. |
| **Deauthentication test** | Continuous, targeted deauth frames against the selected AP. |
| **Handshake capture** | Captures the WPA 4-way handshake to a `.pcap` on the device. |
| **PMKID capture** | Requests and stores PMKIDs from the target AP. |
| **Auto-hunt** | Walks a target list: tries PMKID first, then deauth + handshake, one network at a time. |
| **Evil twin** | Clones the target SSID with a captive portal, validates a submitted passphrase against the real AP, and records the result. |
| **Beacon flood** | Floods with a custom prefix, clones of real networks, or a built-in name database. |
| **Repeater** | NATs the ESP32's uplink so you keep internet access while attached. |
| **On-device files** | Browse, download, convert, and delete captures from the browser. |
| **Live status** | WebSocket feed plus a JSON status endpoint for the current state and target. |

All firmware, HTML, CSS, and JavaScript are compiled into the image — the web UI
is served from flash, not from an SD card or the internet.

## Hardware

| Item | Requirement |
|---|---|
| Board | ESP32 (original ESP32 / WROOM-32). Not ESP32-C3/C6/S2/S3 — the radio and partition layout differ. |
| Flash | 4 MB minimum (the layout below uses 2 MB app + 1.75 MB storage). |
| Radio | 2.4 GHz only. |
| Power | A stable 5 V supply; brown-outs show up as random AP dropouts. |
| Cable | USB **data** cable for flashing. |

An external antenna helps range but is not required.

## Requirements

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/v5.1/) **v5.1** (CI uses the `espressif/idf:release-v5.1` image; `dependencies.lock` pins 5.1.0).
- Python 3.8+ and `git`.
- The custom partition table in `partitions.csv`, applied through the committed `sdkconfig`.

Dependencies are resolved automatically by the component manager:

- [`joltwallet/littlefs`](https://components.espressif.com/components/joltwallet/littlefs) 1.20.1 — on-device storage
- `espressif/httpd`, `cJSON`, and the WiFi/netif stack from ESP-IDF

## Build and flash

```sh
git clone https://github.com/mamun0xf/specter32.git
cd specter32

. $IDF_PATH/export.sh
idf.py set-target esp32     # first checkout only
idf.py build
```

Flash and watch the boot log:

```sh
idf.py -p /dev/ttyUSB0 flash monitor
```

On macOS the port is usually `/dev/cu.usbserial-*`; on Windows, `COMx`.

Prefer not to install ESP-IDF? Grab the three binaries from the **Build Specter32
Firmware** GitHub Actions artifact and flash them manually:

```sh
esptool.py --chip esp32 -p /dev/ttyUSB0 \
  write_flash 0x1000   bootloader.bin \
              0x9000   partition-table.bin \
              0x20000  specter32.bin
```

Those offsets are specific to this project, not to ESP-IDF in general: the
bootloader offset comes from `CONFIG_BOOTLOADER_OFFSET_IN_FLASH`, the partition
table offset from `CONFIG_PARTITION_TABLE_OFFSET=0x9000`, and the app offset from
the 64 KB alignment of the `factory` entry in `partitions.csv`. Always prefer
`idf.py flash`, or read the generated `build/flash_args`, which lists the exact
offsets for the current configuration.

| Image | Offset | Source |
|---|---|---|
| `bootloader.bin` | `0x1000` | `CONFIG_BOOTLOADER_OFFSET_IN_FLASH` |
| `partition-table.bin` | `0x9000` | `CONFIG_PARTITION_TABLE_OFFSET` |
| `specter32.bin` | `0x20000` | `factory` app partition, 64 KB aligned |

## First boot

1. Power the board and join the WiFi network **`Specter32`** with the password
   **`Specter32#esp`**.
2. Open **<http://192.168.4.1>** in a browser.
3. Start with **Scan Networks**, then tap a network to make it the target.

The AP password is a compile-time constant — change it before you carry the
device anywhere (see [Configuration](#configuration)).

The admin AP runs on channel 1 by default; the channel chosen in the UI is saved
to NVS and restored on the next boot.

## Web interface

The single-page UI is served from flash and laid out top to bottom:

| Section | What you can do |
|---|---|
| AP status bar | Current SSID, MAC, and channel of the admin AP. |
| Scan Networks | List nearby APs with signal and security; select one as target. |
| Target | Shows SSID, BSSID, channel; **Scan Clients** lists associated stations. |
| WiFi Repeater | Join an uplink network and NAT it for attached clients. |
| Set AP Channel | Move the admin AP to channels 1–13. |
| Deauthentication | Start/stop a continuous deauth against the target. |
| Handshake Capture | Start/stop EAPOL capture; the result appears under Filesystem Manager. |
| PMKID Capture | Start/stop PMKID capture. |
| Evil Twin | Clone the target SSID, serve the captive portal, report verification status. |
| Auto-Hunt | Set PMKID and handshake time budgets, then walk the target list automatically. |
| Beacon Flood | Pick Custom/Clone/Random mode, prefix, and count. |
| Filesystem Manager | Refresh, convert to `.hc22000`, download, delete, or wipe storage. |
| Status bar | Last action / current state. |

There is **no login** on the web UI. Anyone who can join the admin AP has full
control of the device, so treat the AP password as the only access control.

## HTTP API

Every action in the UI is a plain JSON call, so the device can be scripted with
`curl` from a client attached to the SoftAP. Paths are relative to
`http://192.168.4.1`.

### Device and scanning

| Method | Path | Body | Purpose |
|---|---|---|---|
| `GET` | `/api/ap-info` | — | Admin AP SSID, MAC, channel. |
| `GET` | `/api/status` | — | Current state, target SSID/BSSID/channel. |
| `GET` | `/api/scan` | — | Scan APs: `{success, networks:[{ssid,bssid,rssi,channel,auth}]}`. |
| `POST` | `/api/target` | `{"ssid":"…","bssid":"aa:bb:…"}` | Select the target. |
| `POST` | `/api/wifi/set-channel` | `{"channel":6}` | Move the admin AP to a channel. |
| `GET` | `/api/scan-clients/start` | — | Begin client discovery on the target. |
| `GET` | `/api/scan-clients/results` | — | `{success, clients:["aa:bb:…"]}`. |

### Tests and captures

| Method | Path | Body | Purpose |
|---|---|---|---|
| `POST` | `/api/deauth/start` | — | Continuous deauth against the target. |
| `POST` | `/api/deauth/stop` | — | Stop deauth. |
| `POST` | `/api/capture/start` | — | Start EAPOL capture. |
| `POST` | `/api/capture/stop` | — | Stop capture. |
| `POST` | `/api/pmkid/start` | — | Start PMKID capture. |
| `POST` | `/api/pmkid/stop` | — | Stop PMKID capture. |
| `POST` | `/api/attack/auto/start` | `{"pmkid_time":5,"handshake_time":10}` | Auto-hunt with per-stage timeouts (seconds). |
| `POST` | `/api/attack/beacon/start` | `{"ssid":"prefix","amount":20,"mode":0}` | Beacon flood; mode `0` custom, `1` clone, `2` database. |
| `POST` | `/api/attack/beacon/stop` | — | Stop beacon flood. |
| `POST` | `/api/attack/eviltwin/start` | — | Start the evil twin against the target. |
| `POST` | `/api/attack/eviltwin/stop` | — | Restore the normal admin AP. |
| `GET` | `/api/attack/eviltwin/status` | — | `{status:"idle"|"success"|"fail"}`. |

### Repeater

| Method | Path | Body | Purpose |
|---|---|---|---|
| `POST` | `/api/router/connect` | `{"ssid":"…","password":"…"}` | Join an uplink AP and enable NAT. |
| `POST` | `/api/router/disconnect` | — | Leave the uplink. |
| `GET` | `/api/router/status` | — | Human-readable repeater state. |

### Storage

| Method | Path | Body | Purpose |
|---|---|---|---|
| `GET` | `/api/files` | — | `{success, files:[{filename,size}]}`. |
| `GET` | `/api/download?file=NAME` | — | Download a file from littlefs. |
| `POST` | `/api/delete` | `{"name":"FILE"}` | Delete one file. |
| `POST` | `/api/reset` | — | Format the storage partition. |
| `POST` | `/api/convert` | `{"name":"FILE.pcap"}` | Convert a capture to `.hc22000`; returns `new_file`. |
| `POST` | `/api/set-time` | `{"timestamp":1735689600}` | Set the device clock (Unix seconds). |

A WebSocket at `/ws` pushes state changes to the UI. The captive portal answers
every unknown `GET` path, including the portal's own submission endpoint
`POST /get_wifi_password`.

Example:

```sh
curl -s http://192.168.4.1/api/scan
curl -s -X POST http://192.168.4.1/api/target \
     -d '{"ssid":"LabNet","bssid":"aa:bb:cc:dd:ee:ff"}'
curl -s -X POST http://192.168.4.1/api/capture/start
```

## Captures and files

Everything lives in a littlefs partition mounted at `/littlefs`:

| File | Contents |
|---|---|
| `<ssid>.pcap` | Standard libpcap capture (link type 105, 802.11). PMKID captures include a synthetic beacon so analysis tools keep the SSID. |
| `<ssid>.hc22000` | Hashcat HC22000 lines (`WPA*01*` for PMKID, `WPA*02*` for a handshake), produced by `/api/convert`. |
| `credentials.json` | Evil-twin results: `ssid`, `bssid`, and the submitted password. |

`credentials.json` is stored **in plaintext** on the device. Download and remove
it after an assessment.

The storage partition is 1.75 MB, so long captures can fill it. Download and
delete files between runs, or use **Reset Data** to format the partition.

## Project layout

```text
specter32/
├── CMakeLists.txt              # ESP-IDF project (project: specter32)
├── partitions.csv              # 2 MB app + 1.75 MB littlefs + coredump
├── sdkconfig                   # committed: 4 MB flash, custom partitions, HTTPD/WS
├── dependencies.lock           # pinned component versions (IDF 5.1.0)
├── main/
│   └── app_main.c              # boot order: NVS → netif → fs → wifi → web
├── components/
│   ├── wifi_manager/           # SoftAP, scans, target, evil-twin AP, repeater/NAPT
│   ├── packet_handler/         # raw 802.11 TX: deauth, beacon, PVC
│   ├── attack_manager/         # state machine, captures, auto-hunt, beacon flood
│   ├── evil_twin_manager/      # portal flow + passphrase verification
│   ├── filesystem_manager/     # littlefs, pcap writer, HC22000 converter
│   └── web_server/             # HTTP/WS API + embedded UI
│       └── web/                # index.html, style.css, script.js, captive_portal.html
└── .github/workflows/build.yml # CI: build with IDF 5.1, upload artifacts
```

Each component has its own `CMakeLists.txt` and, where third-party code is used,
an `idf_component.yml`.

## Configuration

The defaults worth reviewing before flashing:

| Setting | Location | Default |
|---|---|---|
| Admin SSID | `components/wifi_manager/include/wifi_manager.h` (`SOFTAP_SSID`) | `Specter32` |
| Admin password | same file (`SOFTAP_PASS`) | `Specter32#esp` |
| Max AP clients | same file (`SOFTAP_MAX_STA_CONN`) | 4 |
| Scan result slots | same file (`MAX_SCAN_RESULTS`) | 20 |
| Tracked clients | `components/attack_manager/include/attack_manager.h` (`MAX_CLIENTS`) | 20 |
| AP address | `components/wifi_manager/wifi_manager.c` | `192.168.4.1/24` |
| Flash size / partitions | `sdkconfig` + `partitions.csv` | 4 MB |
| Partition table offset | `sdkconfig` (`CONFIG_PARTITION_TABLE_OFFSET`) | `0x9000` |
| App image offset | `partitions.csv` (`factory`, 64 KB aligned) | `0x20000` |
| Log level | `sdkconfig` (`CONFIG_LOG_DEFAULT_LEVEL`) | Info |

The AP password must be 8–63 characters for WPA2-PSK. If you change the
partition table, keep the littlefs partition type at `0x83` — the storage code
formats it by subtype name (`storage`).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Specter32` AP never appears | Insufficient power, or a board that is not an original ESP32. Check the serial log for brown-out resets. |
| Cannot open `192.168.4.1` | Still associated with another network, or the AP channel moved. Reconnect to the AP and check the status bar. |
| `No handshake found` on convert | The capture has no complete 4-way handshake and no PMKID. Recapture with traffic on the target. |
| Capture file is empty/0 bytes | Attack stopped before any relevant frame; the firmware deletes empty captures on stop. |
| Build fails on partition sizes | Use the committed `sdkconfig` and `partitions.csv`; a `sdkconfig.old` or a locally regenerated config will fall back to a 1 MB app partition. |
| Short range / dropped clients | On-board antenna and USB power. Move closer, use a better supply, or fit an external antenna. |
| Web UI loads but actions time out | The radio is busy with a scan; single-radio ESP32 cannot scan and serve simultaneously for long. |

## Author

**Abdullah Al Mamun**
[`mamun0xf@proton.me`](mailto:mamun0xf@proton.me) · GitHub [@mamun0xf](https://github.com/mamun0xf)

## License

MIT — see [LICENSE](LICENSE).

Specter32 is provided for authorized security testing, research, and education.
The author accepts no liability for misuse or for any damage caused by this
software.
