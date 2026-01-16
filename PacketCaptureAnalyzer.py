import tkinter as tk
import tkinter.font as tkFont #열 너비 조정하려고 가져옴
from tkinter import ttk, messagebox
from scapy.layers.http import HTTP #HTTP는 별도로 가져옴
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
import struct
import time

packets_data = []
protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0}
ip_traffic = {}

def _dns_qtype_str(qtype):
    dns_qtypes = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA"
    }
    return dns_qtypes.get(qtype, str(qtype))

def icmp_type_meaning(type_num, code):
    meanings = {
        0: "Echo (ping) reply",
        3: {0: "Network unreachable", 1: "Host unreachable", 3: "Port unreachable"},
        8: "Echo (ping) request",
        11: "Time Exceeded",
    }
    if type_num in meanings:
        if isinstance(meanings[type_num], dict):
            return meanings[type_num].get(code, "")
        else:
            return meanings[type_num]
    return ""

def get_packet_detail(raw_pkt):
    detail = []

    #IP 헤더
    if raw_pkt.haslayer(IP):
        ip = raw_pkt[IP]
        detail.append(f"◼ Internet Protocol Version {ip.version}, Src: {ip.src}, Dst: {ip.dst}")
        detail.append(f"    ▪ Version: {ip.version}")
        detail.append(f"    ▪ Header Length: {ip.ihl * 4} bytes ({ip.ihl})")
        dscp = (ip.tos & 0xfc) >> 2
        ecn = ip.tos & 0x3
        detail.append(f"    ▪ Differentiated Services Field: 0x{ip.tos:02x} (DSCP: CS{dscp}, ECN: {'ECT' if ecn else 'Not-ECT'})")
        detail.append(f"    ▪ Total Length: {ip.len}")
        detail.append(f"    ▪ Identification: 0x{ip.id:04x} ({ip.id})")
        flags_val = int(ip.flags)
        detail.append(
            f"    ▪ Flags: 0x{flags_val:01x}, Don't fragment" if flags_val == 2
            else f"    ▪ Flags: 0x{flags_val:01x}"
        )
        detail.append(f"    ▪ Fragment Offset: {ip.frag}")
        detail.append(f"    ▪ Time To Live: {ip.ttl}")
        detail.append(f"    ▪ Protocol: {ip.proto}")
        detail.append(f"    ▪ Header Checksum: 0x{ip.chksum:04x} [validation disabled]")
        detail.append(f"    ▪ [Header checksum status: Unverified]")
        detail.append(f"    ▪ Source Address: {ip.src}")
        detail.append(f"    ▪ Destination Address: {ip.dst}")

    #ICMP 상세
    if raw_pkt.haslayer(ICMP):
        icmp = raw_pkt[ICMP]
        detail.append("◼ Internet Control Message Protocol")
        meaning = icmp_type_meaning(icmp.type, icmp.code)
        detail.append(f"    ▪ Type: {icmp.type} ({meaning})")
        detail.append(f"    ▪ Code: {icmp.code}")
        detail.append(f"    ▪ Checksum: 0x{icmp.chksum:04x} [correct]")
        detail.append(f"    ▪ [Checksum Status: Good]")
        identifier = getattr(icmp, "id", None)
        if identifier is not None:
            id_le = int.from_bytes(identifier.to_bytes(2, 'big'), 'little')
            detail.append(f"    ▪ Identifier (BE): {identifier} (0x{identifier:04x})")
            detail.append(f"    ▪ Identifier (LE): {id_le} (0x{id_le:04x})")
        sequence = getattr(icmp, "seq", None)
        if sequence is not None:
            seq_le = int.from_bytes(sequence.to_bytes(2, 'big'), 'little')
            detail.append(f"    ▪ Sequence Number (BE): {sequence} (0x{sequence:04x})")
            detail.append(f"    ▪ Sequence Number (LE): {seq_le} (0x{seq_le:04x})")
        if hasattr(icmp, 'payload') and hasattr(icmp.payload, 'load'):
            data_bytes = icmp.payload.load
            
            if len(data_bytes) >= 8:
                try:
                    timestamp_bytes = data_bytes[:8]
                    timestamp_ms = struct.unpack('>Q', timestamp_bytes)[0]
                    timestamp_sec = timestamp_ms / 1000000000.0
                    time_str = time.strftime('%b %d, %Y %H:%M:%S', time.localtime(timestamp_sec))
                    detail.append(f"    ▪ Timestamp from icmp data: {time_str}.{int((timestamp_sec % 1) * 1000000000):09d} KST")
                    detail.append(f"    ▪ [Timestamp from icmp data (relative): {timestamp_sec:.8f} seconds]")
                except:
                    detail.append("     ▪ Timestamp from icmp data: (파싱 불가)")
            detail.append(f"    ▪ Data: {data_bytes.hex()}")
            detail.append(f"    ▪ [Data Length: {len(data_bytes)}]")

            if icmp.type in {3, 11} and len(data_bytes) >= 20:
                found = False
                for ip_offset in range(0, 12):
                    try:
                        inner_pkt = IP(data_bytes[ip_offset:])
                        #내부 IP
                        detail.append(f"          ‣ Internet Protocol Version {inner_pkt.version}, Src: {inner_pkt.src}, Dst: {inner_pkt.dst}")
                        detail.append(f"            └ Version: {inner_pkt.version}")
                        detail.append(f"            └ Header Length: {inner_pkt.ihl * 4} bytes ({inner_pkt.ihl})")
                        dscp = (inner_pkt.tos & 0xfc) >> 2
                        ecn = inner_pkt.tos & 0x3
                        detail.append(f"            └ Differentiated Services Field: 0x{inner_pkt.tos:02x} (DSCP: CS{dscp}, ECN: {'ECT' if ecn else 'Not-ECT'})")
                        detail.append(f"            └ Total Length: {inner_pkt.len}")
                        detail.append(f"            └ Identification: 0x{inner_pkt.id:04x} ({inner_pkt.id})")
                        flags_val = int(inner_pkt.flags)
                        detail.append(
                            f"            └ Flags: 0x{flags_val:01x}, Don't fragment" if flags_val == 2 
                            else f"            └ Flags: 0x{flags_val:01x}"
                        )
                        detail.append(f"            └ Fragment Offset: {inner_pkt.frag}")
                        detail.append(f"            └ Time To Live: {inner_pkt.ttl}")
                        detail.append(f"            └ Protocol: {inner_pkt.proto}")
                        detail.append(f"            └ Header Checksum: 0x{inner_pkt.chksum:04x} [validation disabled]")
                        detail.append(f"            └ [Header checksum status: Unverified]")
                        detail.append(f"            └ Source Address: {inner_pkt.src}")
                        detail.append(f"            └ Destination Address: {inner_pkt.dst}")

                        #내부 UDP
                        if inner_pkt.haslayer(UDP):
                            udp = inner_pkt[UDP]
                            detail.append(f"          ‣ User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}")
                            detail.append(f"            └ Source Port: {udp.sport}")
                            detail.append(f"            └ Destination Port: {udp.dport}")
                            detail.append(f"            └ Length: {udp.len}")
                            detail.append(f"            └ Checksum: 0x{udp.chksum:04x} [unverified]")
                            detail.append(f"            └ [Checksum status: Unverified]")
                            detail.append(f"            └ [Stream index: 1]")
                            detail.append(f"            └ [Timestamps]")
                            payload_bytes = bytes(udp.payload)
                            detail.append(f"            └ UDP payload ({len(payload_bytes)} bytes)")
                        found = True
                        break
                    except Exception:
                        continue
                    if not found:
                        detail.append("          ‣ [원본 IP/UDP 추출 실패]")
        else:
            detail.append("     ▪ Data: ")
            detail.append("     ▪ [Data Length: 0]")

    #HTTP 요청
    if raw_pkt.haslayer(HTTPRequest):
        http = raw_pkt[HTTPRequest]
        detail.append("◼ Hypertext Transfer Protocol")
        
        method  = getattr(http, "Method", b"").decode(errors="ignore")
        path    = getattr(http, "Path",   b"").decode(errors="ignore")
        version = getattr(http, "Http_Version", b"").decode(errors="ignore")
        first_line = f"{method} {path} {version}".strip()
        detail.append(f"    ▪ {first_line}\\r\\n")

        def _hdr(field_name, header_name):
            val = getattr(http, field_name, None)
            if isinstance(val, bytes):
                val = val.decode(errors="ignore")
            if val:
                detail.append(f"    ▪ {header_name}: {val}\\r\\n")

        _hdr("Host",       "Host")
        _hdr("User_Agent", "User-Agent")
        _hdr("Accept",     "Accept")

        detail.append("      \\r\\n")

        host_val = getattr(http, "Host", b"").decode(errors="ignore") if hasattr(http, "Host") else ""
        uri = f"http://{host_val}{path}" if host_val else "?"
        detail.append(f"    ▪ [Full request URI: {uri}]")
        detail.append( "    ▪ [HTTP request 1/1]")

    #HTTP 응답
    elif raw_pkt.haslayer(HTTPResponse):
        http = raw_pkt[HTTPResponse]
        detail.append("◼ Hypertext Transfer Protocol")

        version = getattr(http, "Http_Version", b"").decode(errors="ignore")
        status  = getattr(http, "Status_Code",  b"").decode(errors="ignore")
        reason  = getattr(http, "Reason_Phrase", b"").decode(errors="ignore")
        first_line = f"{version} {status} {reason}".strip()
        detail.append(f"    ▪ {first_line}\\r\\n")

        def _hdr(field_name, header_name):
            val = getattr(http, field_name, None)
            if isinstance(val, bytes):
                val = val.decode(errors="ignore")
            if val:
                detail.append(f"    ▪ {header_name}: {val}\\r\\n")

        _hdr("Date",                      "Date")
        _hdr("Content_Type",              "Content-Type")
        _hdr("Content_Length",            "Content-Length")
        _hdr("Connection",                "Connection")
        _hdr("Strict_Transport_Security", "Strict-Transport-Security")
        _hdr("Location",                  "Location")
        detail.append( "    ▪ [HTTP request 1/1]")

        if hasattr(http, "raw_packet_cache") and http.raw_packet_cache:
            raw_bytes = http.raw_packet_cache
        elif hasattr(http, "load"):
            raw_bytes = http.load
        else:
            raw_bytes = b""

        try:
            text = raw_bytes.decode(errors="ignore")
        except:
            text = ""

        body_part = ""
        if text and "\r\n\r\n" in text:
            _, body_part = text.split("\r\n\r\n", 1)

        if body_part:
            body_len = len(body_part.encode("utf-8"))
            detail.append(f"    ▪ File Data: {body_len} bytes")
            detail.append(f"◼ Line-based text data: {body_len} bytes")
            for line in body_part.splitlines():
                detail.append(f"    {line}\\r\\n")
        else:
            detail.append("    ▪ File Data: 0 bytes")

    #TCP 상세
    elif raw_pkt.haslayer(TCP):
        tcp = raw_pkt[TCP]
        detail.append(f"◼ Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}, Seq: {tcp.seq}, Len: {len(tcp.payload)}")
        detail.append(f"    ▪ Source Port: {tcp.sport}")
        detail.append(f"    ▪ Destination Port: {tcp.dport}")
    
        detail.append(f"    ▪ [Stream index: 0]")  
        detail.append(f"    ▪ [Conversation completeness: Complete, WITH_DATA (31)]")  
    
        detail.append(f"    ▪ [TCP Segment Len: {len(tcp.payload)}]")
    
        detail.append(f"    ▪ Sequence Number: {tcp.seq} (relative sequence number)")
        detail.append(f"    ▪ Sequence Number (raw): {tcp.seq}")
        detail.append(f"    ▪ [Next Sequence Number: {tcp.seq + len(tcp.payload)} (relative sequence number)]")
    
        detail.append(f"    ▪ Acknowledgment Number: {tcp.ack}")
        detail.append(f"    ▪ Acknowledgment number (raw): {tcp.ack}")
    
        hdrlen_raw = (tcp.dataofs if hasattr(tcp, 'dataofs') else (tcp.off if hasattr(tcp, 'off') else None))
        hdrlen = hdrlen_raw * 4 if hdrlen_raw is not None else 0
        detail.append(f"    ▪ {bin(hdrlen_raw)[2:].zfill(4)} .... = Header Length: {hdrlen} bytes ({hdrlen_raw})")
    
        flags_value = int(tcp.flags)
        flags_str = []
        if flags_value & 0x01: flags_str.append("FIN")
        if flags_value & 0x02: flags_str.append("SYN")
        if flags_value & 0x04: flags_str.append("RST")
        if flags_value & 0x08: flags_str.append("PSH")
        if flags_value & 0x10: flags_str.append("ACK")
        if flags_value & 0x20: flags_str.append("URG")
        flags_desc = '/'.join(flags_str) if flags_str else "NONE"
        detail.append(f"    ▪ Flags: 0x{flags_value:03x} ({flags_desc})")
    
        detail.append(f"      ‣ Window: {tcp.window}")
        detail.append(f"      ‣ [Calculated window size: {tcp.window}]")
        detail.append(f"      ‣ Checksum: 0x{tcp.chksum:04x} [unverified]")
        detail.append(f"      ‣ [Checksum Status: Unverified]")
        detail.append(f"      ‣ Urgent Pointer: {tcp.urgptr}")


    #UDP 상세
    elif raw_pkt.haslayer(UDP):
        udp = raw_pkt[UDP]
        detail.append(f"◼ User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}")
        detail.append(f"    ▪ Source Port: {udp.sport}")
        detail.append(f"    ▪ Destination Port: {udp.dport}")
        detail.append(f"    ▪ Length: {udp.len}")
        detail.append(f"    ▪ Checksum: 0x{udp.chksum:04x} [unverified]")
        detail.append(f"    ▪ [Checksum status: Unverified]")
        detail.append(f"    ▪ [Stream index: 1]")
        detail.append(f"    ▪ [Timestamps]")
        payload_bytes = bytes(udp.payload)
        detail.append(f"    ▪ UDP payload ({len(payload_bytes)} bytes)")
        #DNS가 있으면 출력
        if raw_pkt.haslayer(DNS):
            dns = raw_pkt[DNS]
            detail.append(f"◼ Domain Name System ({'query' if getattr(dns, 'qr', 0) == 0 else 'response'})")
            detail.append(f"    ▪ Transaction ID: 0x{getattr(dns,'id',0):04x}")
            if raw_pkt.haslayer(UDP):
                raw_bytes = bytes(raw_pkt[UDP].payload)
                if len(raw_bytes) >= 4:
                    dns_flags_bytes = raw_bytes[2:4]
                    dns_flags_val = int.from_bytes(dns_flags_bytes, 'big')
                    detail.append(f"    ▪ Flags: 0x{dns_flags_val:04x}")
                else:
                    detail.append(f"    ▪ Flags: (UDP payload too short)")
            else:
                detail.append(f"    ▪ Flags: (Cannot extract from TCP/raw)")
            detail.append(f"    ▪ Questions: {getattr(dns,'qdcount',0)}")
            detail.append(f"    ▪ Answer RRs: {getattr(dns,'ancount',0)}")
            detail.append(f"    ▪ Authority RRs: {getattr(dns,'nscount',0)}")
            detail.append(f"    ▪ Additional RRs: {getattr(dns,'arcount',0)}")
            #Queries
            if getattr(dns, "qdcount", 0) > 0 and hasattr(dns, "qd") and dns.qd:
                queries = dns.qd if isinstance(dns.qd, list) else [dns.qd]
                for i, q in enumerate(queries, 1):
                    try:
                        qname = getattr(q, "qname", b"").decode(errors="ignore").rstrip(".")
                        qtype_val = getattr(q, "qtype", 0)
                        qtype_str = _dns_qtype_str(qtype_val)
                        qclass_val = getattr(q, "qclass", 0)
                        qclass_str = "IN" if qclass_val == 1 else str(qclass_val)
                        detail.append(f"    ▪ Queries")
                        detail.append(f"          ‣ {qname}: type {qtype_str}, class {qclass_str}")
                        detail.append(f"            └ Name: {qname}")
                        detail.append(f"            └ [Name Length: {len(qname)}]")
                        label_count = qname.count('.')+1 if qname else 0
                        detail.append(f"            └ [Label Count: {label_count}]")
                        detail.append(f"            └ Type: {qtype_str}")
                        detail.append(f"            └ Class: {qclass_str} (0x{qclass_val:04x})")
                    except Exception:
                        pass
            #Answers
            if getattr(dns, "ancount", 0) > 0 and getattr(dns, "qr", 0) == 1:
                answers = dns.an if isinstance(dns.an, list) else [dns.an]
                detail.append(f"    ▪ Answers")
                for a in answers:
                    try:
                        aname = getattr(a, "rrname", b"")
                        if isinstance(aname, bytes):
                            aname = aname.decode(errors="ignore")
                        aname = aname.rstrip(".")

                        atype_val = getattr(a, "type", 0)
                        atype_str = _dns_qtype_str(atype_val)

                        aclass_val = getattr(a, "rclass", 0)
                        aclass_str = "IN" if aclass_val == 1 else str(aclass_val)

                        ttl = getattr(a, "ttl", "")

                        rdlen = getattr(a, "rdlen", None)
                        if rdlen is None:
                            rdata_field = getattr(a, "rdata", b"")
                            if isinstance(rdata_field, bytes):
                                rdlen = len(rdata_field)
                            else:
                                rdlen = len(str(rdata_field))

                        rdata = getattr(a, "rdata", "")
                        if isinstance(rdata, bytes):
                            rdata_str = rdata.decode(errors="ignore")
                        else:
                            rdata_str = str(rdata)

                        detail.append(f"          ‣ {aname}: type {atype_str}, class {aclass_str}, addr {rdata_str}")
                        detail.append(f"            └ Name: {aname}")
                        detail.append(f"            └ Type: {atype_str}")
                        detail.append(f"            └ Class: {aclass_str} (0x{aclass_val:04x})")
                        detail.append(f"            └ Time to live: {ttl}")
                        detail.append(f"            └ Data length: {rdlen}")
                        detail.append(f"            └ Address: {rdata_str}")
                    except Exception:
                        pass
        detail.append(f"◼ Data ({len(payload_bytes)} bytes)")
        detail.append(f"    ▪ Data: {payload_bytes.hex()}")
        detail.append(f"    ▪ [Length: {len(payload_bytes)}]")
    return "\n".join(detail)

def packet_callback(packet):
    proto, src, dst, sport, dport, info = "", "", "", "", "", ""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        #TCP 인지 먼저 확인
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            #HTTP 요청/응답이면 여기서 처리
            if packet.haslayer(HTTPRequest):
                proto = "HTTP"
                http = packet[HTTPRequest]
                method = getattr(http, "Method", b"").decode(errors="ignore")
                host   = getattr(http, "Host",   b"").decode(errors="ignore")
                path   = getattr(http, "Path",   b"").decode(errors="ignore")
                info = f"HTTP Request | {method} http://{host}{path}"
            elif packet.haslayer(HTTPResponse):
                proto = "HTTP"
                info = "HTTP Response"
            else:
                #그냥 일반 TCP
                proto = "TCP"
                info = f"{src}:{sport} → {dst}:{dport}"

        #UDP 처리
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if packet.haslayer(DNS):
                dns = packet[DNS]
                domain = getattr(dns.qd, "qname", b"").decode(errors="ignore") if hasattr(dns,"qd") and dns.qd else ""
                domain = domain.rstrip(".")
                info = f"DNS | {src}:{sport} → {dst}:{dport} | {domain}"
            else:
                info = f"{src}:{sport} → {dst}:{dport}"

        elif packet.haslayer(ICMP):
            proto = "ICMP"
            info = f"{src} → {dst} type={packet[ICMP].type}"

        else:
            proto = "IP"
            info = f"{src} → {dst}"

        packets_data.append({
            "No": len(packets_data)+1,
            "Proto": proto,
            "Src": src,
            "Dst": dst,
            "Sport": sport,
            "Dport": dport,
            "Info": info,
            "RawPacket": packet
        })
        if proto in protocol_count:
            protocol_count[proto] += 1
        ip_traffic[src] = ip_traffic.get(src, 0) + 1
        tree.insert("", tk.END, values=(len(packets_data), proto, src, dst, sport, dport, info))

def start_capture():
    cnt = int(entry_count.get())
    clear_data()
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, count=cnt,))
    sniff_thread.daemon = True
    sniff_thread.start()

def clear_data():
    tree.delete(*tree.get_children())
    packets_data.clear()
    protocol_count.update({"TCP": 0, "UDP": 0, "ICMP": 0})
    ip_traffic.clear()

def search_packet():
    term = entry_search.get().strip()
    for i in tree.get_children():
        tree.delete(i)
    for pkt in packets_data:
        if term in pkt["Src"] or term in pkt["Dst"] or term.upper() in pkt["Proto"] or term in pkt["Info"]:
            tree.insert("", tk.END, values=tuple(list(pkt.values())[:7]))

def filter_packets():
    ip_f = entry_ip.get().strip()
    port_f = entry_port.get().strip()
    proto_f = entry_proto.get().strip().upper()
    port_exact = None
    if port_f:
        try:
            port_exact = int(port_f)
        except Exception:
            port_exact = None
    for i in tree.get_children():
        tree.delete(i)
    for pkt in packets_data:
        cond = True
        if ip_f and (ip_f not in pkt["Src"] and ip_f not in pkt["Dst"]):
            cond = False
        if port_exact is not None:
            if (pkt["Sport"] != port_exact and pkt["Dport"] != port_exact):
                cond = False
        if proto_f and pkt["Proto"] != proto_f:
            cond = False
        if cond:
            tree.insert("", tk.END, values=tuple(list(pkt.values())[:7]))
    
#상세 분석 창 너비 조정 코드 추가함
def on_packet_select(event):
    selected = tree.focus()
    if not selected:
        return
    values = tree.item(selected)["values"]
    if not values:
        return
    idx = int(values[0]) - 1
    pkt = packets_data[idx]
    raw_pkt = pkt.get("RawPacket")
    detail = get_packet_detail(raw_pkt)
    
    font_name = "D2Coding"
    font_size = 10
    font = tkFont.Font(family=font_name, size=font_size)
    lines = detail.splitlines()
    max_pixel_width = max(font.measure(line) for line in lines) if lines else 300
    n_lines = len(lines)
    text_width = max_pixel_width + 30
    text_height = font.metrics("linespace") * (n_lines+1) + 30

    popup = tk.Toplevel(root)
    popup.title("패킷 상세 분석")
    popup.configure(bg="#e6f4fd")
    text_widget = tk.Text(
        popup,
        wrap=tk.NONE,
        font=(font_name, font_size),
        width=1,
        height=1
    )
    text_widget.insert(tk.END, detail)
    text_widget.config(state=tk.DISABLED)
    text_widget.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
    popup.geometry(f"{text_width}x{text_height}")

root = tk.Tk()
root.title("패킷 캡쳐·분석 프로그램")
root.configure(bg="#e6f4fd")
root.geometry("1012x400")

frame = tk.Frame(root, bg="#e6f4fd")
frame.pack(pady=5)
tk.Label(frame, text="캡처할 패킷 개수:", bg="#e6f4fd").pack(side=tk.LEFT)
entry_count = tk.Entry(frame, width=10)
entry_count.insert(0, "50")
entry_count.pack(side=tk.LEFT)
tk.Button(frame, text="캡처 시작", command=start_capture).pack(side=tk.LEFT, padx=3)
frame_filter = tk.Frame(root, bg="#e6f4fd")
frame_filter.pack(pady=2)
tk.Label(frame_filter, text="IP:", bg="#e6f4fd").pack(side=tk.LEFT)
entry_ip = tk.Entry(frame_filter, width=15)
entry_ip.pack(side=tk.LEFT)
tk.Label(frame_filter, text="포트:", bg="#e6f4fd").pack(side=tk.LEFT)
entry_port = tk.Entry(frame_filter, width=8)
entry_port.pack(side=tk.LEFT)
tk.Label(frame_filter, text="프로토콜:", bg="#e6f4fd").pack(side=tk.LEFT)
entry_proto = tk.Entry(frame_filter, width=8)
entry_proto.pack(side=tk.LEFT)
tk.Button(frame_filter, text="필터링", command=filter_packets).pack(side=tk.LEFT, padx=3)

frame_search = tk.Frame(root, bg="#e6f4fd")
frame_search.pack()
tk.Label(frame_search, text="검색:", bg="#e6f4fd").pack(side=tk.LEFT)
entry_search = tk.Entry(frame_search, width=15)
entry_search.pack(side=tk.LEFT)
tk.Button(frame_search, text="검색", command=search_packet).pack(side=tk.LEFT, padx=3)

columns = ("No.", "Protocol", "Source", "Destination", "Source Port", "Destination Port", "Info")
tree = ttk.Treeview(root, columns=columns, show="headings", height=18)

for col in columns:
    tree.heading(col, text=col)

tree.column("No.",              width=40,  minwidth=60,  stretch=False)
tree.column("Protocol",         width=80,  minwidth=80,  stretch=False)
tree.column("Source",           width=120, minwidth=180, stretch=False)
tree.column("Destination",      width=120, minwidth=180, stretch=False)
tree.column("Source Port",      width=110,  minwidth=90,  stretch=False)
tree.column("Destination Port", width=110, minwidth=110, stretch=False)
tree.column("Info",             width=420, minwidth=300, stretch=False)
   
tree.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

tree.bind("<<TreeviewSelect>>", on_packet_select)

root.mainloop()
