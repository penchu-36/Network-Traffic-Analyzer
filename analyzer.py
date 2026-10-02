#!/usr/bin/env python3
"""Network Traffic Analyzer — capture live packets for a window, tally them
per protocol and per source IP, then draw a bar chart.

Defensive / educational. Capture ONLY on your own machine and your own
network. On Windows this needs Npcap installed and an Administrator shell.

    python analyzer.py                 # 60s capture on the default interface
    python analyzer.py --seconds 30    # shorter window
    python analyzer.py --iface "Wi-Fi" # force an interface
    python analyzer.py --list          # show interfaces, then exit
    python analyzer.py --demo          # self-check, no capture / no admin
"""
import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import (
    ARP, DNS, ICMP, IP, IPv6, TCP, UDP, conf, sniff,
)
from scapy.error import Scapy_Exception

ICMPV6 = 58  # IANA next-header number for ICMPv6


def classify(pkt):
    """Return (protocol_label, source_key) for one packet.

    Protocol is read top-down: an app protocol (DNS) wins over its transport
    (UDP), transport wins over the bare network layer. Source is the IP/IPv6
    address, or the ARP sender IP; anything with no L3 address is 'non-IP'
    (keeps MAC addresses out of the chart — privacy + no real host IDs leak).

    Truncated / adversarial frames must never kill a live capture, so any
    parse error is bucketed as 'Malformed' rather than raised.
    """
    try:
        if ARP in pkt:
            return "ARP", pkt[ARP].psrc

        src = pkt[IP].src if IP in pkt else pkt[IPv6].src if IPv6 in pkt else "non-IP"

        if DNS in pkt:
            proto = "DNS"
        elif TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt or (IPv6 in pkt and pkt[IPv6].nh == ICMPV6):
            proto = "ICMP"  # ponytail: nh==58 misses ICMPv6 behind IPv6 ext headers, rare on a LAN
        elif IP in pkt or IPv6 in pkt:
            proto = "IP-other"
        else:
            proto = "Other"
        return proto, src
    except Exception:
        return "Malformed", "non-IP"


def capture(seconds, iface):
    """Sniff for `seconds`, counting protocols and source IPs as packets arrive.
    store=False so we tally on the fly and never hold packets in memory."""
    protos, sources = Counter(), Counter()

    def tally(pkt):
        proto, src = classify(pkt)
        protos[proto] += 1
        sources[src] += 1

    print(f"Capturing for {seconds}s on {iface or conf.iface} ... (Ctrl-C to stop early)")
    sniff(iface=iface, timeout=seconds, prn=tally, store=False)
    return protos, sources


def print_summary(protos, sources):
    total = sum(protos.values())
    print(f"\n{total} packets captured\n")
    print("By protocol:")
    for name, n in protos.most_common():
        print(f"  {name:<10} {n:>6}")
    print("\nTop source IPs:")
    for ip, n in sources.most_common(15):
        print(f"  {ip:<20} {n:>6}")


def draw_chart(protos, sources, out_dir):
    """Two stacked bar charts (protocol + top source IPs). Saves a timestamped
    PNG always, and opens a window if a display is available."""
    import matplotlib.pyplot as plt

    top_src = sources.most_common(15)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 9))

    p_names, p_vals = zip(*protos.most_common()) if protos else ([], [])
    ax1.bar(p_names, p_vals, color="#2a6fdb")
    ax1.set_title("Packets by protocol")
    ax1.set_ylabel("packets")

    s_names, s_vals = zip(*top_src) if top_src else ([], [])
    ax2.bar(s_names, s_vals, color="#d9534f")
    ax2.set_title("Packets by source IP (top 15)")
    ax2.set_ylabel("packets")
    ax2.tick_params(axis="x", rotation=45)
    for lbl in ax2.get_xticklabels():
        lbl.set_ha("right")

    fig.suptitle(f"Network traffic — {datetime.now():%Y-%m-%d %H:%M:%S}")
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    png = out_dir / f"traffic_{datetime.now():%Y%m%d_%H%M%S}.png"
    fig.savefig(png, dpi=120)
    print(f"\nChart saved: {png}")
    try:
        plt.show()
    except Exception as e:  # ponytail: headless / no-Tk shell still gets the PNG
        print(f"(no display window: {e})")


def demo():
    """Self-check: run known packets through classify and assert the tally.
    Needs no admin and no Npcap — proves the classification logic in isolation."""
    from scapy.all import Ether
    from scapy.layers.inet6 import IPv6 as _IPv6, ICMPv6EchoRequest

    pkts = [
        Ether() / IP(src="1.1.1.1") / TCP(),                       # TCP
        Ether() / IP(src="1.1.1.1") / UDP(dport=53) / DNS(),       # DNS, same src
        Ether() / ARP(psrc="2.2.2.2"),                             # ARP
        Ether() / IP(src="3.3.3.3") / ICMP(),                      # ICMPv4
        Ether() / _IPv6(src="::1") / ICMPv6EchoRequest(),          # ICMPv6 -> ICMP too
        Ether() / _IPv6(src="::1") / TCP(),                        # TCP over IPv6
        Ether() / IP(src="4.4.4.4"),                               # IP w/ no transport
        Ether(),                                                   # non-IP, Other
    ]
    protos, sources = Counter(), Counter()
    for p in pkts:
        # round-trip through bytes so layers are parsed like a real capture
        proto, src = classify(Ether(bytes(p)))
        protos[proto] += 1
        sources[src] += 1

    assert protos["TCP"] == 2, protos
    assert protos["DNS"] == 1, protos
    assert protos["ARP"] == 1, protos
    assert protos["ICMP"] == 2, protos          # IPv4 ICMP + IPv6 ICMPv6
    assert protos["IP-other"] == 1, protos
    assert protos["Other"] == 1, protos
    assert sources["1.1.1.1"] == 2, sources     # TCP + DNS from same host
    assert sources["2.2.2.2"] == 1, sources     # ARP sender IP
    assert sources["non-IP"] == 1, sources      # bare Ethernet frame

    # A frame scapy can't dissect is delivered as Raw in a live capture — must
    # classify cleanly (this is how truncated/garbage frames actually arrive).
    from scapy.packet import Raw
    assert classify(Raw(b"\x00\x01\x02")) == ("Other", "non-IP"), "Raw runt"
    # And the parse-error guard itself must never raise, whatever it's handed.
    assert classify(object()) == ("Malformed", "non-IP"), "guard catches anything"
    print("demo: OK —", dict(protos))


def main():
    ap = argparse.ArgumentParser(description="Capture and chart network traffic by protocol and source IP.")
    ap.add_argument("--seconds", type=int, default=60, help="capture window (default 60)")
    ap.add_argument("--iface", default=None, help="interface to capture on (default: auto)")
    ap.add_argument("--out", default="captures", help="directory for saved PNGs")
    ap.add_argument("--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("--demo", action="store_true", help="run the self-check and exit")
    args = ap.parse_args()

    if args.demo:
        demo()
        return
    if args.list:
        print(conf.ifaces)
        return
    if args.seconds <= 0:
        sys.exit("--seconds must be a positive number (scapy treats 0 as capture-forever).")

    try:
        protos, sources = capture(args.seconds, args.iface)
    except PermissionError:
        sys.exit("Permission denied — run this in an Administrator shell (Npcap needs it).")
    except (OSError, ValueError, Scapy_Exception) as e:
        sys.exit(f"Capture failed ({e}). Check the interface name (try --list) and that Npcap is installed.")

    if not protos:
        print("No packets captured. Wrong interface, or the network was silent — try --list.")
        return
    print_summary(protos, sources)
    draw_chart(protos, sources, Path(args.out))


if __name__ == "__main__":
    main()
