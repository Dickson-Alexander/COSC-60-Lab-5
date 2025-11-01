import subprocess, re
import time
from scapy.all import sniff, RadioTap, Dot11, Dot11Elt, Dot11ProbeReq, get_if_hwaddr, sendp, Dot11Beacon, Raw, LLC, SNAP
rssi = None
found_channel = False
vendor_channel = None
ap_mac = None

# --- helpers ----------------------------------------------------

def sh(*args):
    return subprocess.run(args, check=False, capture_output=True, text=True)

def ensure_monitor(iface="wlan0mon", phy="wlan0"):
    """
    Create/enable a monitor interface 'wlan0mon' from base 'wlan0' (or whatever yours is).
    Safe to call multiple times.
    """
    # Best-effort: bring base down, set type monitor (or create a new iface), bring up
    sh("sudo", "ip", "link", "set", phy, "down")
    # try in-place monitor
    r = sh("sudo", "iw", phy, "set", "type", "monitor")
    if r.returncode != 0:
        # fallback: create a dedicated mon iface if driver supports it
        sh("sudo", "iw", "dev", iface, "del")
        sh("sudo", "iw", "dev", phy, "interface", "add", iface, "type", "monitor")
        phy = iface
    sh("sudo", "ip", "link", "set", phy, "up")
    print(f"[+] Monitor mode enabled on {phy}")
    return phy  # return the iface you should sniff on

def restore_managed(iface="wlan0"):
    """Try to restore managed mode after the lab."""
    sh("sudo", "ip", "link", "set", iface, "down")
    sh("sudo", "iw", iface, "set", "type", "managed")
    sh("sudo", "ip", "link", "set", iface, "up")
    print(f"[+] Restored managed mode on {iface}")


def set_channel(iface, ch: int):
    """Set iface to channel ch (use iwconfig per lab hint)."""
    subprocess.run(["sudo", "iwconfig", iface, "channel", str(ch)], check=False)

    
def process_packet(pkt):
    global rssi, found_channel, vendor_channel, ap_mac

    if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(RadioTap)):
        return

    # Parse SSID and Vendor IE
    ssid = None
    vendor_bytes = None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:  # SSID
            ssid = elt.info.decode(errors="ignore")
        elif elt.ID == 221:  # Vendor Specific IE
            vendor_bytes = bytes(elt.info)
        elt = elt.payload.getlayer(Dot11Elt)

    if ssid != "CS60":
        return

    # Save RSSI and AP MAC (beacon's transmitter/BSSID)
    rssi = pkt[RadioTap].dBm_AntSignal
    ap_mac = pkt.addr2  # or pkt.addr3; beacons usually have addr2==addr3

    # We parse channel from vendor_bytes if format known (Used chatGPT to write the regEx matching script after first printing out the Vendor E Hex)
    if vendor_bytes:
        try:
            msg = vendor_bytes.decode("ascii", errors="ignore")
            m = re.search(r'CHANNEL[_\s-]*(\d{1,2})', msg)
            if m:
                vendor_channel = int(m.group(1))  # e.g., 3
                print(f"[+] Vendor hint: switch to channel {vendor_channel}")
        except Exception:
            pass

    found_channel = True


def stop_filter(pkt):
    return found_channel
    

def locate_host(iface):
    """
    Hop channels 1..11 until we see CS60 beacons; track RSSI for room hunt.
    If a Vendor IE hints a new channel, switch to it.
    """
    global rssi, found_channel, vendor_channel

    channel = 1
    while not found_channel:
        set_channel(iface, channel)
        # brief sniff; process_packet() sets found_channel & fills rssi/ap_mac
        sniff(iface=iface, prn=process_packet, stop_filter=lambda _: found_channel, timeout=3.0, store=False)
        if not found_channel:
            channel = 1 if channel == 11 else channel + 1

    print(f"[+] Found CS60 on channel {channel}, RSSI ≈ {rssi} dBm, AP={ap_mac}")

    # Keep listening a bit to print RSSI for hallway room search
    t0 = time.time()
    while time.time() - t0 < 10:
        sniff(iface=iface, prn=lambda p: (process_packet(p), print(f"RSSI: {rssi} dBm")) if rssi is not None else None,
              timeout=1.0, store=False)

    # If process_packet captured vendor bytes, parse channel hint
    # You can stash vendor bytes globally there; here we just trust vendor_channel if set
    if vendor_channel is not None:
        set_channel(iface, vendor_channel)
        print(f"[+] Switched to vendor-specified channel {vendor_channel}")



def retrieve_code(iface, netid: str):
    """
    On the new channel, send a Layer-2 frame to the AP with your NetID.
    Listen for a reply frame carrying your flag and return it.
    """
    assert ap_mac, "AP MAC unknown; run locate_host() first"
    src = get_if_hwaddr(iface)

    # Build L2 802.11 data frame (to DS=0, addr1=AP, addr2=STA, addr3=AP)
    dot11 = Dot11(type=2, subtype=0, addr1=ap_mac, addr2=src, addr3=ap_mac)
    payload = Raw(netid.encode())
    frame = RadioTap()/dot11/LLC()/SNAP()/payload

    # Send a few times
    for _ in range(5):
        sendp(frame, iface=iface, verbose=False)
        time.sleep(0.05)

    flag = {"value": None}

    def got_flag(pkt):
        # Look for data frames from AP to us that carry a printable payload
        if not pkt.haslayer(Dot11) or pkt.type != 2:
            return False
        if pkt.addr2 != ap_mac:
            return False
        raw = pkt.getlayer(Raw)
        if not raw:
            return False
        try:
            text = raw.load.decode(errors="ignore").strip()
        except Exception:
            return False
        if text and len(text) >= 3:
            flag["value"] = text
            return True
        return False

    sniff(iface=iface, stop_filter=got_flag, timeout=3.0, store=False)
    if flag["value"]:
        print(f"[+] Received flag: {flag['value']}")
    else:
        print("[!] No flag seen; try re-sending a few more times or adjust filters.")
    return flag["value"]

def main():
    ""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="wlan0", help="monitor-mode interface (e.g., wlan0)")
    parser.add_argument("--netid", required=True, help="Your Dartmouth ID (e.g., f00abc3)")
    args = parser.parse_args()

    print("[*] Scanning for CS60 beacons…")

    mon = ensure_monitor("wlan0mon", "wlan0")
    locate_host(mon)

    print("[*] Requesting code from AP…")
    flag = retrieve_code(mon, args.netid)

    if flag:
        print("\n=== FLAG SUBMISSION ===")
        print(f"Location: ECSC 019")
        print(f"Code: {flag}")
        print("=======================\n")

    restore_managed("wlan0") 


if __name__ == "__main__":
    main()




    

          
