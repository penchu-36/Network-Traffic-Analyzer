# Network Traffic Analyzer

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Dependencies](https://img.shields.io/badge/deps-scapy%20%2B%20matplotlib-orange.svg)

**See what's actually flowing across your network.** This tool watches the packets going in and out of your computer for a set number of seconds, then shows you a simple bar chart of **what kind** of traffic it was (the protocols) and **who** was sending it (the source addresses).

![Example output](docs/screenshot.png)

---

> **New here? Read the next two sections.**
> **Just want to run it?** Jump to [Quick start](#quick-start).
> **Want every flag and the internals?** Jump to [Command reference](#command-reference) and [How it works](#how-it-works-the-technical-tour).

## Contents

- [What is this, in plain English?](#what-is-this-in-plain-english)
- [What am I looking at? (reading the chart)](#what-am-i-looking-at-reading-the-chart)
- [Who is this for?](#who-is-this-for)
- [Quick start](#quick-start)
- [Full setup (step by step)](#full-setup-step-by-step)
- [Command reference](#command-reference)
- [Understanding the output](#understanding-the-output)
- [Using it inside your own project](#using-it-inside-your-own-project)
- [How it works (the technical tour)](#how-it-works-the-technical-tour)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Glossary](#glossary)
- [Ethics & authorization](#ethics--authorization)
- [Development](#development)
- [License](#license)

---

## What is this, in plain English?

Think of the internet like a **postal system**. Everything your computer sends or receives — opening a website, streaming a video, sending a message — is broken into thousands of tiny "postcards" called **packets**. Each packet has a label on the front saying who it's from, who it's going to, and what type it is.

Normally your computer reads only the packets meant for it and quietly throws the labels away — you never see them. You just get the finished result: the loaded page, the played video.

**This tool stands next to the mail slot and reads the front of every packet as it goes by**, for however long you tell it to. It doesn't open the packets or read their contents — it just keeps a tally: *"250 packets were web traffic, 40 were name-lookups, and that one device over there sent 9,000 of them."* Then it draws that tally as a chart.

Why would you want that? Because you can't understand — or protect — something you can't see. This is the difference between "my internet feels slow" and "**that** device is flooding the network with **this** kind of traffic." It's a basic, honest **visibility** tool.

## What am I looking at? (reading the chart)

The tool produces **two bar charts stacked on top of each other** (see the image above):

- **Top chart — "Packets by protocol":** how many packets of each *type* were seen. Taller bar = more of that type. On a normal machine **TCP** (regular web/app traffic) is usually the tallest.
- **Bottom chart — "Packets by source IP":** the 15 *addresses* that sent the most packets. The tallest bar is usually your own computer or your router — i.e. your loudest talker.

It also prints the same numbers as a text table in the terminal, so you get the information even if no chart window opens.

**A protocol is just "what kind of traffic it is." A source IP is just "which device/server sent it."** That's the whole idea. (Not sure what TCP or DNS means? See [Understanding the output](#understanding-the-output) — it's explained there.)

## Who is this for?

- **Curious / learning:** a hands-on way to *see* the invisible traffic on your own machine and learn how networks actually talk.
- **Students & security learners:** a small, readable example of live packet capture and protocol classification (the code is one file).
- **Defenders / sysadmins:** a quick "what's talking, and how much?" snapshot — handy for spotting a noisy or unexpected host.
- **Developers building something bigger:** you can [import it as a library](#using-it-inside-your-own-project) and reuse the capture-and-count logic in your own project without writing packet-parsing code yourself.

---

## Quick start

If you already have Python and just want to see it work:

```bash
# 1. get the code
git clone https://github.com/jafeeri/network-traffic-analyzer.git
cd network-traffic-analyzer

# 2. install the two libraries it needs
pip install -r requirements.txt

# 3. prove the logic works — needs NO admin, NO driver, captures nothing
python analyzer.py --demo
```

If `--demo` prints `demo: OK — {...}`, you're set. To do a **real capture** you need one extra piece (a capture driver) and admin rights — see [Full setup](#full-setup-step-by-step). Then:

```bash
python analyzer.py --seconds 30    # watch traffic for 30 seconds, then chart it
```

---

## Full setup (step by step)

### 1. Python
You need **Python 3.11 or newer**. Check with:
```bash
python --version
```
If that fails, install Python from [python.org](https://www.python.org/downloads/) (on Windows, tick *"Add Python to PATH"* during install).

### 2. (Recommended) a virtual environment
A **virtual environment** ("venv") is an isolated, per-project copy of Python's package folder, so this project's libraries can't clash with anything else on your machine. It's optional but tidy:

```bash
python -m venv .venv
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate
```
Your prompt now shows `(.venv)`. To leave it later, type `deactivate`.
> On Windows, if PowerShell blocks the activate script, run once in that window:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### 3. Install the libraries
```bash
pip install -r requirements.txt
```
This installs **scapy** (captures and reads packets) and **matplotlib** (draws the chart).

### 4. Install a packet-capture driver (only needed for real captures)
Reading raw packets needs a small system driver. `--demo` and `--list` do **not** need it; live capture does.

- **Windows:** install **[Npcap](https://npcap.com)**. During install, tick **"Install Npcap in WinPcap API-compatible Mode."**
- **Linux:** usually already present (`libpcap`); if not, install it via your package manager (e.g. `sudo apt install libpcap0.8`).
- **macOS:** already present.

### 5. Run with the right permissions
Capturing raw packets is a privileged operation, so:

- **Windows:** open **PowerShell as Administrator** (right-click → *Run as administrator*), then `cd` back to the project (and re-activate the venv there if you made one).
- **Linux / macOS:** put `sudo` in front of the command, e.g. `sudo python analyzer.py`.

You're ready. Try `python analyzer.py --list` first to see your network interfaces, then do a capture.

---

## Command reference

```
python analyzer.py [--seconds N] [--iface NAME] [--out DIR] [--list] [--demo]
```

| Option | What it does | Default |
|---|---|---|
| *(no options)* | Capture on the auto-detected interface for 60 seconds, then summarize + chart. | — |
| `--seconds N` | How long to capture, in seconds. Must be a positive number. | `60` |
| `--iface NAME` | Capture on a specific network interface (name from `--list`). | auto-detect |
| `--out DIR` | Folder to save the chart PNG into (created if missing). | `captures` |
| `--list` | Print the available network interfaces, then exit. *(no capture)* | — |
| `--demo` | Run the built-in self-check and exit. *(no capture, no admin, no driver)* | — |

### Examples

```bash
python analyzer.py                     # 60-second capture, auto interface
python analyzer.py --seconds 15        # quick 15-second look
python analyzer.py --iface "Wi-Fi"     # capture on the interface named "Wi-Fi"
python analyzer.py --seconds 60 --out reports   # save the PNG into reports/
python analyzer.py --list              # which interfaces can I capture on?
python analyzer.py --demo              # is the tool working? (safe, offline)
```

### Tips
- **Generate some traffic while it captures** (open a website, run `ping google.com`) so the chart has something interesting to show.
- **Stop early** by pressing **Ctrl-C** — it will still summarize whatever it caught so far.
- On Windows the chart opens in a window; **close that window** to let the program finish (the PNG is already saved before the window opens).

---

## Understanding the output

A real run prints something like this:

```
29768 packets captured

By protocol:
  TCP          19826
  UDP           9756
  ARP             74
  DNS             56
  ICMP            23

Top source IPs:
  192.168.1.24           6568
  140.82.121.4           6492
  ...
Chart saved: captures\traffic_20260821_054135.png
```

**The protocols, in plain terms:**

| Label | What it means |
|---|---|
| **TCP** | The reliable, connection-based workhorse — websites, email, file transfer, most apps. Usually the biggest bar. |
| **UDP** | Fast "fire-and-forget" traffic — video calls, games, streaming, and some lookups. |
| **DNS** | Name lookups — turning `google.com` into an address. Like using a phonebook. |
| **ARP** | Local "who has this address?" chatter between devices on your own network. |
| **ICMP** | Network control & diagnostics — `ping`, and on IPv6, "neighbor discovery." |
| **IP-other** | IP traffic that isn't one of the transports above. |
| **Other** | Frames with no IP address at all (some low-level local-network protocols). |
| **Malformed** | The rare frame the tool couldn't parse. Counted honestly instead of crashing. |

**Source IPs:** these are the addresses (IPv4 like `192.168.1.24`, or IPv6 like `2606:4700::1111`) that sent packets. Addresses starting `192.168.`, `10.`, or `fe80::` are devices on your **local** network; others are servers out on the internet. Frames without any IP address are grouped as **`non-IP`**.

> **On privacy:** the tool records only these labels — the *type* of packet and the *sender's address*. It never looks inside a packet at its contents, and it never records hardware (MAC) addresses.

---

## Using it inside your own project

The whole tool is one file (`analyzer.py`) with small, reusable functions, so you can drop it into your own Python project instead of running it from the command line.

**Capture and get the raw tallies:**
```python
from analyzer import capture, print_summary, draw_chart
from pathlib import Path

# capture() needs admin/sudo + a capture driver, just like the CLI.
# iface=None lets it auto-pick the default interface.
protocols, sources = capture(seconds=30, iface=None)

# protocols and sources are plain collections.Counter objects:
print(protocols.most_common(3))       # e.g. [('TCP', 19826), ('UDP', 9756), ...]
print(sources["192.168.1.24"])        # how many packets that host sent

# reuse the built-in reporting if you want it:
print_summary(protocols, sources)
draw_chart(protocols, sources, Path("my_output_dir"))
```

**Classify a single packet you already have** (e.g. from your own scapy `sniff`, or reading a `.pcap`):
```python
from analyzer import classify
proto, src = classify(a_scapy_packet)   # -> ("DNS", "192.168.1.24")
```

Because `protocols` and `sources` are standard [`collections.Counter`](https://docs.python.org/3/library/collections.html#collections.Counter) objects, you can feed them straight into your own dashboards, alerts, CSV exports, or thresholds — no need to touch packet parsing at all.

---

## How it works (the technical tour)

Every packet is a set of nested envelopes — the **protocol stack**:

```
Ethernet / Wi-Fi  →  IP / IPv6 / ARP  →  TCP / UDP / ICMP  →  DNS ...
   (link, L2)          (network, L3)        (transport, L4)     (app, L7)
```

1. **Capture** — `scapy.sniff(iface, timeout, prn=callback, store=False)` delivers each frame to a callback as it arrives. `store=False` means packets are counted on the fly and never held in memory, so RAM usage stays flat no matter how much traffic passes.
2. **Classify** — `classify()` reads the stack **top-down** and returns `(protocol, source)`. The most informative label wins (a DNS lookup is counted as `DNS`, not `UDP`). The source is the layer-3 address (IPv4, IPv6, or the ARP sender); a frame with no layer-3 address becomes `non-IP`, which keeps hardware addresses out of the output. **ICMPv6** is detected via the IPv6 next-header value (`58`). Any frame that can't be parsed is bucketed as `Malformed` rather than allowed to crash the capture.
3. **Aggregate** — two `collections.Counter` objects accumulate the tallies; `.most_common()` yields sorted output for free.
4. **Report** — a text summary prints, and a two-panel matplotlib bar chart is saved as a timestamped PNG and shown in a window.

**Design choices worth knowing:**
- **One dependency does the heavy lifting.** scapy provides both live capture *and* full layered parsing (`pkt[IP].src`, `DNS in pkt`), so there's no hand-rolled packet parser.
- **Crash-safety over completeness.** A live capture must survive malformed/truncated frames; the classifier is wrapped so a single bad packet can never kill a 60-second run.
- **Metadata only.** By design it counts protocol + source and never inspects payloads — the minimal, defensible footprint for a visibility tool.

The classifier ships with a runnable self-check (`python analyzer.py --demo`) that verifies every branch — including IPv6, ICMPv6, and malformed-frame handling — with no capture, admin, or driver required.

---

## Troubleshooting & FAQ

**`ModuleNotFoundError: No module named 'scapy'`**
The libraries aren't installed in the Python you're running. Activate your venv (`.\.venv\Scripts\Activate.ps1` / `source .venv/bin/activate`) and run `pip install -r requirements.txt`. On Windows, remember the **Administrator** shell needs the venv activated too (or just install the deps globally).

**`Permission denied — run this in an Administrator shell`**
Live capture needs elevated rights. Open PowerShell *as Administrator* (Windows) or use `sudo` (Linux/macOS).

**`Capture failed (Interface '...' not found !)`**
The interface name is wrong. Run `python analyzer.py --list` and copy an exact name into `--iface`.

**`No packets captured.`**
Either you're on the wrong interface (try `--list` and pick your active one), or the network was silent. Re-run and browse a website or `ping` something during the capture.

**Nothing happens on Windows / "sniff" sees no interfaces.**
Npcap isn't installed (or not in WinPcap-compatible mode). Install it from [npcap.com](https://npcap.com).

**The chart window never opened, but it said "Chart saved."**
You're likely on a headless/remote shell with no display. That's fine — open the saved PNG in the `captures/` folder.

**Is this legal / safe to run?**
On **your own machine and your own network**, yes — see [Ethics & authorization](#ethics--authorization). It reads only metadata and stores no packet contents.

**Does it slow down or interfere with my network?**
No. It passively *reads* copies of packets; it doesn't send, block, or modify anything.

---

## Glossary

- **Packet / frame** — a small chunk of network data with address labels wrapped around it.
- **Protocol** — the *kind* of traffic (TCP, UDP, DNS, …); rules for how two machines talk.
- **IP address** — a device's address on a network (IPv4 `192.168.1.24`, or the longer IPv6 `2606:4700::1111`).
- **Source IP** — the address a packet came *from*.
- **Interface** — a specific network connection on your machine (e.g. `Wi-Fi`, `Ethernet`).
- **Packet capture / sniffing** — reading copies of packets off a network interface.
- **Npcap / libpcap** — the system driver that lets software capture packets.
- **Promiscuous mode** — telling the network card to hand over *all* frames it can hear, not just the ones addressed to you. (This tool works fine without it.)

---

## Ethics & authorization

This is a **defensive / educational** tool. Only capture on **a machine you own and a network you own or are explicitly authorized to monitor.** Sniffing traffic on networks you don't control is illegal in most jurisdictions. The tool records only metadata (protocol type and source address) and never inspects or stores packet contents — but the responsibility for lawful, authorized use is yours.

## Development

- Run the self-check anytime (no capture needed): `python analyzer.py --demo`
- The code is deliberately small — one file, standard library plus scapy and matplotlib. Contributions and issues welcome.

## License

[MIT](LICENSE) © Ali Jaffery
