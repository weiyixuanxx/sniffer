import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import IP, TCP, UDP, ARP, ICMP, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from parsers import ProtocolParser, AppLayerSession
from sniffer import PacketSniffer

class SnifferGUI:
    """
    构建并管理嗅探器的图形用户界面。
    """

    def __init__(self, root):
        self.root = root
        self.root.title("网络嗅探工具")
        self.root.geometry("900x700")
        
        # 将 Sniffer 对象与 GUI 关联，并传入自身作为回调
        self.sniffer = PacketSniffer(self)
        self.packet_count = 0
        self.packets_data = [] # 存储ID和完整数据包的元组

        self.create_widgets()

    def create_widgets(self):
        # --- 创建主框架 ---
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- 控制区 ---
        control_frame = ttk.LabelFrame(main_frame, text="控制面板", padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(control_frame, text="过滤规则 (BPF):").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_entry = ttk.Entry(control_frame)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.filter_entry.insert(0, "ip") # 默认过滤规则

        self.start_button = ttk.Button(control_frame, text="开始", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="停止", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(control_frame, text="清空", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(control_frame, text="状态: 已停止")
        self.status_label.pack(side=tk.LEFT, padx=10)

        # --- PanedWindow 用于分割列表和详情 ---
        paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- 数据包列表区 ---
        list_frame = ttk.Frame(paned_window, padding=(0, 5, 0, 0))
        columns = ('No.', 'Src', 'Dst', 'Protocol', 'Info')
        self.packet_list = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.packet_list.heading(col, text=col)
        
        self.packet_list.column('No.', width=60, stretch=tk.NO, anchor='center')
        self.packet_list.column('Src', width=150)
        self.packet_list.column('Dst', width=150)
        self.packet_list.column('Protocol', width=80, anchor='center')
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_list.yview)
        self.packet_list.configure(yscroll=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        paned_window.add(list_frame, weight=1)

        # --- 详细信息区 ---
        detail_frame = ttk.LabelFrame(paned_window, text="数据包详情", padding="10")
        self.detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=15)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        paned_window.add(detail_frame, weight=1)

        # --- 绑定事件 ---
        self.packet_list.bind('<<TreeviewSelect>>', self.show_packet_details)

    def start_sniffing(self):
        filter_exp = self.filter_entry.get()
        self.sniffer.start(filter_exp)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.filter_entry.config(state=tk.DISABLED)

    def stop_sniffing(self):
        self.sniffer.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.filter_entry.config(state=tk.NORMAL)

    def clear_display(self):
        self.packet_list.delete(*self.packet_list.get_children())
        self.detail_text.delete('1.0', tk.END)
        self.packets_data.clear()
        self.packet_count = 0
        self.status_label.config(text=f"状态: 已清空")

    def display_packet(self, packet):
        """由 PacketSniffer 线程调用的回调函数，用于在 GUI 中显示数据包。"""
        self.packet_count += 1
        protocol, src, dst, info = "Unknown", "N/A", "N/A", ""
        
        # 确定协议和地址
        if IP in packet: src, dst = packet[IP].src, packet[IP].dst
        elif ARP in packet: src, dst = packet[ARP].psrc, packet[ARP].pdst
        
        # 确定最高层协议用于显示
        if ARP in packet: protocol = "ARP"
        elif ICMP in packet: protocol = "ICMP"
        elif TCP in packet: protocol = "TCP"
        elif UDP in packet: protocol = "UDP"
        
        if packet.haslayer(DNS): protocol = "DNS"
        elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse): protocol = "HTTP"
        elif packet.haslayer(TCP) and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
            if packet.haslayer(Raw) and packet[Raw].load.startswith(b'\x16\x03'):
                protocol = "TLS/SSL"

        # 摘要信息
        if TCP in packet: info = f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet: info = f"{packet[UDP].sport} -> {packet[UDP].dport}"

        item_id = self.packet_list.insert('', 'end', values=(self.packet_count, src, dst, protocol, info))
        self.packets_data.append((item_id, packet))
        self.packet_list.yview_moveto(1.0) # 自动滚动到底部

    def show_packet_details(self, event):
        """当用户在列表中选择一个项目时触发。"""
        selected_item = self.packet_list.selection()
        if not selected_item: return
            
        # 根据选择的 item_id 查找完整的数据包
        packet = next((pkt for item_id, pkt in self.packets_data if item_id == selected_item[0]), None)
        
        if packet:
            # 使用解析器生成详细信息
            details = ProtocolParser(packet).parse()
            app_details = AppLayerSession(packet).parse()
            
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, "--- 协议解析 ---\n" + details)
            if app_details:
                self.detail_text.insert(tk.END, "\n--- 应用层交互 ---\n" + app_details)

    def update_status(self, message):
        """由 PacketSniffer 线程调用的回调函数，用于更新状态栏。"""
        self.status_label.config(text=f"状态: {message}")