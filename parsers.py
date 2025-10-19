from scapy.all import IP, TCP, UDP, ARP, ICMP, Raw, Ether
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

# 用于跟踪DNS请求和响应的全局字典
dns_requests = {}

class ProtocolParser:
    """
    一个用于解析不同网络协议数据包的类。
    """

    def __init__(self, packet):
        self.packet = packet

    def parse(self):
        """
        解析数据包并返回一个格式化的字符串，显示各层协议的详细信息。
        """
        output = ""
        if Ether in self.packet:
            eth_layer = self.packet[Ether]
            output += f"--- Ethernet ---\n"
            output += f"  源 MAC: {eth_layer.src}\n"
            output += f"  目的 MAC: {eth_layer.dst}\n"
            output += f"  类型: {hex(eth_layer.type)}\n"

        if ARP in self.packet:
            arp_layer = self.packet[ARP]
            output += "\n--- ARP ---\n"
            output += f"  操作: {'请求 (1)' if arp_layer.op == 1 else '响应 (2)'}\n"
            output += f"  发送方 MAC: {arp_layer.hwsrc}\n"
            output += f"  发送方 IP: {arp_layer.psrc}\n"
            output += f"  目标 MAC: {arp_layer.hwdst}\n"
            output += f"  目标 IP: {arp_layer.pdst}\n"

        if IP in self.packet:
            ip_layer = self.packet[IP]
            output += "\n--- IP ---\n"
            output += f"  版本: {ip_layer.version}\n"
            output += f"  头部长度: {ip_layer.ihl}\n"
            output += f"  总长度: {ip_layer.len}\n"
            output += f"  ID: {ip_layer.id}\n"
            output += f"  TTL: {ip_layer.ttl}\n"
            output += f"  协议: {ip_layer.proto}\n"
            output += f"  源 IP: {ip_layer.src}\n"
            output += f"  目的 IP: {ip_layer.dst}\n"

        if TCP in self.packet:
            tcp_layer = self.packet[TCP]
            output += "\n--- TCP ---\n"
            output += f"  源端口: {tcp_layer.sport}\n"
            output += f"  目的端口: {tcp_layer.dport}\n"
            output += f"  序列号: {tcp_layer.seq}\n"
            output += f"  确认号: {tcp_layer.ack}\n"
            output += f"  标志: {tcp_layer.flags}\n"
            output += f"  窗口大小: {tcp_layer.window}\n"

        if UDP in self.packet:
            udp_layer = self.packet[UDP]
            output += "\n--- UDP ---\n"
            output += f"  源端口: {udp_layer.sport}\n"
            output += f"  目的端口: {udp_layer.dport}\n"
            output += f"  长度: {udp_layer.len}\n"

        if ICMP in self.packet:
            icmp_layer = self.packet[ICMP]
            output += "\n--- ICMP ---\n"
            output += f"  类型: {icmp_layer.type}\n"
            output += f"  代码: {icmp_layer.code}\n"
            
        if IGMP in self.packet:
            igmp_layer = self.packet[IGMP]
            output += "\n--- IGMP ---\n"
            output += f"  类型: {igmp_layer.type}\n"
            output += f"  最大响应时间: {igmp_layer.maxresp}\n"
            output += f"  多播地址: {igmp_layer.gaddr}\n"
            
        if Raw in self.packet:
            output += f"\n--- 原始数据 ---\n{self.packet[Raw].load.hex()}\n"

        return output

class AppLayerSession:
    """
    用于解析和显示应用层协议的交互。
    """
    def __init__(self, packet):
        self.packet = packet

    def parse(self):
        """
        解析应用层数据并返回格式化的字符串。
        """
        output = ""
        # DNS 解析
        if self.packet.haslayer(DNSQR) and self.packet.getlayer(DNS).qr == 0:
            query = self.packet.getlayer(DNSQR)
            dns_layer = self.packet.getlayer(DNS)
            dns_requests[dns_layer.id] = query.qname.decode()
            output += f"--- DNS 查询 ---\n"
            output += f"  ID: {dns_layer.id}\n"
            output += f"  查询: {query.qname.decode()}\n"
            output += f"  类型: {query.qtype}\n"

        elif self.packet.haslayer(DNSRR) and self.packet.getlayer(DNS).qr == 1:
            dns_layer = self.packet.getlayer(DNS)
            if dns_layer.id in dns_requests:
                output += f"--- DNS 响应 ---\n"
                output += f"  ID: {dns_layer.id}\n"
                output += f"  请求域名: {dns_requests[dns_layer.id]}\n"
                for i in range(dns_layer.ancount):
                    rr = dns_layer.an[i]
                    if rr.type == 1: # A record
                        output += f"  - IP 地址: {rr.rdata}\n"
                    else:
                        output += f"  - 响应数据: {rr.rdata}\n"
                del dns_requests[dns_layer.id]

        # HTTP 解析
        if self.packet.haslayer(HTTPRequest):
            http_layer = self.packet[HTTPRequest]
            output += f"--- HTTP 请求 ---\n"
            output += f"  方法: {http_layer.Method.decode()}\n"
            output += f"  主机: {http_layer.Host.decode()}\n"
            output += f"  路径: {http_layer.Path.decode()}\n"

        elif self.packet.haslayer(HTTPResponse):
            http_layer = self.packet[HTTPResponse]
            output += f"--- HTTP 响应 ---\n"
            output += f"  状态码: {http_layer.Status_Code.decode()}\n"
            output += f"  原因: {http_layer.Reason_Phrase.decode()}\n"
            
        # FTP 简单解析
        if self.packet.haslayer(TCP) and (self.packet[TCP].dport == 21 or self.packet[TCP].sport == 21):
            if self.packet.haslayer(Raw):
                payload = self.packet[Raw].load.decode(errors='ignore')
                if any(cmd in payload for cmd in ["USER", "PASS", "STOR", "RETR", "220 ", "230 ", "530 "]):
                    output += f"--- FTP 控制命令/响应 ---\n"
                    output += "  " + payload.strip()

        # HTTPS/TLS 握手识别
        if self.packet.haslayer(TCP) and (self.packet[TCP].dport == 443 or self.packet[TCP].sport == 443):
            if self.packet.haslayer(Raw):
                payload = self.packet[Raw].load
                # 检查 TLS Client Hello (Content Type 22, Handshake Type 1)
                if payload.startswith(b'\x16\x03\x01') and len(payload) > 5 and payload[5] == 1:
                    output += "--- TLS/SSL 握手 (Client Hello) ---\n"
                # 检查 TLS Server Hello
                elif payload.startswith(b'\x16\x03') and len(payload) > 5 and payload[5] == 2:
                    output += "--- TLS/SSL 握手 (Server Hello) ---\n"

        return output