# gui.py

import tkinter as tk
from tkinter import ttk, scrolledtext
import traceback

# 导入所有需要的 scapy 类
from scapy.all import IP, TCP, UDP, ARP, ICMP, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

from parsers import ProtocolParser, AppLayerSession
from sniffer import PacketSniffer

class BarChart(ttk.Frame):
    """一个经过视觉优化的，用于显示条形图的自定义Tkinter控件"""
    def __init__(self, parent, title, data_colors, bg_color, text_color, font_bold):
        super().__init__(parent, style='Dark.TFrame')
        self.data_colors = data_colors
        self.labels = list(data_colors.keys())
        self.bg_color = bg_color
        self.text_color = text_color
        self.font_bold = font_bold
        
        ttk.Label(self, text=title, font=self.font_bold, anchor="center", style='DarkTitle.TLabel').pack(pady=(0, 10), fill="x")
        
        self.canvas = tk.Canvas(self, bg=self.bg_color, height=150, bd=0, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

    def update(self, data_values):
        self.canvas.after_idle(lambda: self._draw_chart(data_values))

    def _draw_chart(self, data_values):
        self.canvas.delete("all")
        canvas_height = self.canvas.winfo_height()
        canvas_width = self.canvas.winfo_width()
        if canvas_width <= 1 or canvas_height <= 1: return

        TOP_MARGIN, BOTTOM_MARGIN = 20, 30
        drawable_height = canvas_height - TOP_MARGIN - BOTTOM_MARGIN
        if drawable_height <= 0: return

        max_value = max(list(data_values.values()) + [1])
        num_bars = len(self.labels)
        if num_bars == 0: return

        bar_width = canvas_width / (num_bars * 2 + 1)
        spacing = bar_width

        for i, label in enumerate(self.labels):
            value = data_values.get(label, 0)
            bar_height = (value / max_value) * drawable_height
            
            x0 = (i + 1) * spacing + i * bar_width
            x1 = x0 + bar_width
            y1_baseline = canvas_height - BOTTOM_MARGIN
            y0_top = y1_baseline - bar_height

            color = self.data_colors[label]
            if value > 0:
                self.canvas.create_rectangle(x0, y0_top, x1, y1_baseline, fill=color, outline=color)
            else:
                self.canvas.create_line(x0, y1_baseline, x1, y1_baseline, fill=color, width=2)

            self.canvas.create_text(x0 + bar_width / 2, y0_top - 5, text=str(value), anchor='s', font=("Segoe UI", 9), fill=self.text_color)
            self.canvas.create_text(x0 + bar_width / 2, y1_baseline + 8, text=label, anchor='n', font=self.font_bold, fill=self.text_color)


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("mini sniffer (魏轶轩)")
        self.root.geometry("1600x1200")

        self.BG_COLOR = '#1e2a31'
        self.FG_COLOR = '#d0d0d0'
        self.ACCENT_BG = '#28363f'
        self.ACCENT_FG = '#ffc107'
        self.BUTTON_BG = '#2c3e50'
        
        self.base_font = ("Microsoft YaHei UI", 10)
        self.bold_font = ("Microsoft YaHei UI", 11, "bold")

        # --- 新增：定义协议颜色映射 ---
        self.protocol_color_map = {
            'ARP': '#3498db',    # 蓝色
            'IP': '#f1c40f',     # 黄色
            'ICMP': '#e74c3c',   # 红色
            'TCP': '#2ecc71',    # 绿色
            'UDP': '#e67e22',    # 橙色
            'HTTP': '#9b59b6',   # 紫色
            'FTP': '#1abc9c',    # 青色
            'DNS': '#d35400',    # 深橙色
            'TLS/SSL': '#5dade2', # 亮蓝色
            'Unknown': self.FG_COLOR # 默认颜色
        }
        
        self.root.configure(bg=self.BG_COLOR)
        self.setup_styles()

        self.sniffer = PacketSniffer(self)
        self.packet_count = 0
        self.packets_data = [] 
        self.protocol_counts = {
            'ARP': 0, 'IP': 0, 'ICMP': 0, 'TCP': 0, 'UDP': 0,
            'HTTP': 0, 'FTP': 0, 'DNS': 0, 'Total': 0
        }
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')

        style.configure('.', background=self.BG_COLOR, foreground=self.FG_COLOR, font=self.base_font, borderwidth=0)
        style.configure('TFrame', background=self.BG_COLOR)
        style.configure('Dark.TFrame', background=self.ACCENT_BG)
        style.configure('TLabel', background=self.BG_COLOR, foreground=self.FG_COLOR)
        style.configure('DarkTitle.TLabel', background=self.ACCENT_BG, foreground=self.FG_COLOR)
        style.configure('TLabelFrame', background=self.BG_COLOR, borderwidth=1, relief="solid")
        style.configure('TLabelFrame.Label', background=self.BG_COLOR, foreground=self.FG_COLOR, font=self.bold_font)
        
        style.map('TButton', 
                background=[('!active', self.BUTTON_BG), ('pressed', self.ACCENT_BG), ('active', self.ACCENT_BG)],
                foreground=[('!active', self.ACCENT_FG), ('pressed', self.FG_COLOR), ('active', self.FG_COLOR)])
        
        style.configure('Treeview', fieldbackground=self.ACCENT_BG, background=self.ACCENT_BG, foreground=self.FG_COLOR, rowheight=25)
        style.configure('Treeview.Heading', background=self.BUTTON_BG, foreground=self.ACCENT_FG, font=self.bold_font, padding=5)
        style.map('Treeview.Heading', background=[('active', self.ACCENT_BG)])
        
        style.configure('Vertical.TScrollbar', background=self.BUTTON_BG, troughcolor=self.BG_COLOR, bordercolor=self.BG_COLOR, arrowcolor=self.ACCENT_FG)

    def create_widgets(self):
        main_paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        left_pane = ttk.Frame(main_paned_window, padding=5)
        main_paned_window.add(left_pane, weight=3)

        right_pane = ttk.Frame(main_paned_window, padding=(10, 5))
        main_paned_window.add(right_pane, weight=2)

        self.create_left_pane_widgets(left_pane)
        self.create_right_pane_widgets(right_pane)

    def create_left_pane_widgets(self, parent):
        control_frame = ttk.LabelFrame(parent, text="控制面板", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(control_frame, text="过滤规则 (BPF):").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_entry = ttk.Entry(control_frame, font=self.base_font)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.filter_entry.insert(0, "")

        self.start_button = ttk.Button(control_frame, text="开始", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(control_frame, text="停止", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = ttk.Button(control_frame, text="清空", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(parent, text="状态: 已停止", padding=(5, 5))
        self.status_label.pack(fill=tk.X)

        sub_paned_window = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        sub_paned_window.pack(fill=tk.BOTH, expand=True)
        
        list_frame = ttk.Frame(sub_paned_window)
        columns = ('No.', 'Src', 'Dst', 'Protocol', 'Info')
        self.packet_list = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns: self.packet_list.heading(col, text=col)
        self.packet_list.column('No.', width=60, stretch=tk.NO, anchor='center')
        self.packet_list.column('Src', width=150); self.packet_list.column('Dst', width=150)
        self.packet_list.column('Protocol', width=80, anchor='center')
        
        # --- 新增：为 Treeview 配置颜色标签 ---
        for proto, color in self.protocol_color_map.items():
            self.packet_list.tag_configure(proto, foreground=color)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_list.yview)
        self.packet_list.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sub_paned_window.add(list_frame, weight=1)

        detail_frame = ttk.LabelFrame(sub_paned_window, text="数据包详情", padding=10)
        self.detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=15, 
            bg=self.ACCENT_BG, fg=self.FG_COLOR, font=self.base_font, bd=0, highlightthickness=0,
            insertbackground=self.ACCENT_FG)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.detail_text.config(state=tk.DISABLED)
        sub_paned_window.add(detail_frame, weight=1)

        self.packet_list.bind('<<TreeviewSelect>>', self.show_packet_details)
    
    def create_right_pane_widgets(self, parent):
        stats_frame = ttk.LabelFrame(parent, text="实时统计", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True)

        def create_chart_section(container, title, colors):
            section_frame = ttk.LabelFrame(container, text=title, padding=10)
            section_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            chart = BarChart(section_frame, title=title, data_colors=colors, bg_color=self.ACCENT_BG, text_color=self.FG_COLOR, font_bold=self.bold_font)
            chart.pack(fill=tk.BOTH, expand=True, pady=5)
            return chart

        self.network_chart = create_chart_section(stats_frame, "网络层", 
            {'ARP': '#3498db', 'IP': '#f1c40f', 'ICMP': '#e74c3c'})
        self.transport_chart = create_chart_section(stats_frame, "传输层", 
            {'TCP': '#2ecc71', 'UDP': '#e67e22'})
        self.app_chart = create_chart_section(stats_frame, "应用层", 
            {'HTTP': '#9b59b6', 'FTP': '#1abc9c', 'DNS': '#d35400'})

    def start_sniffing(self):
        self.clear_display()
        filter_exp = self.filter_entry.get()
        self.sniffer.start(filter_exp)
        self.start_button.config(state=tk.DISABLED); self.stop_button.config(state=tk.NORMAL)
        self.filter_entry.config(state=tk.DISABLED)

    def stop_sniffing(self):
        self.sniffer.stop()
        self.start_button.config(state=tk.NORMAL); self.stop_button.config(state=tk.DISABLED)
        self.filter_entry.config(state=tk.NORMAL)

    def clear_display(self):
        self.packet_list.delete(*self.packet_list.get_children())
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.config(state=tk.DISABLED)
        self.packets_data.clear()
        self.packet_count = 0
        for key in self.protocol_counts: self.protocol_counts[key] = 0
        self.update_stats_display()
        self.status_label.config(text=f"状态: 已清空")

    def update_stats_display(self):
        self.network_chart.update(self.protocol_counts)
        self.transport_chart.update(self.protocol_counts)
        self.app_chart.update(self.protocol_counts)

    def display_packet(self, packet):
        self.packet_count += 1
        
        self.protocol_counts['Total'] += 1
        if ARP in packet: self.protocol_counts['ARP'] += 1
        if IP in packet: self.protocol_counts['IP'] += 1
        if ICMP in packet: self.protocol_counts['ICMP'] += 1
        if TCP in packet: self.protocol_counts['TCP'] += 1
        if UDP in packet: self.protocol_counts['UDP'] += 1
        if DNS in packet: self.protocol_counts['DNS'] += 1
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse): self.protocol_counts['HTTP'] += 1
        if TCP in packet and (packet[TCP].sport in [20, 21] or packet[TCP].dport in [20, 21]):
            self.protocol_counts['FTP'] += 1
        
        try:
            if not hasattr(self, '_after_id') or self._after_id is None:
                self._after_id = self.root.after(100, self._update_stats_callback)
        except tk.TclError: pass

        protocol, src, dst, info = "Unknown", "N/A", "N/A", ""
        if IP in packet: src, dst = packet[IP].src, packet[IP].dst
        elif ARP in packet: src, dst = packet[ARP].psrc, packet[ARP].pdst
        
        if packet.haslayer(DNS): protocol = "DNS"
        elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse): protocol = "HTTP"
        elif TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
            if packet.haslayer(Raw) and packet[Raw].load.startswith(b'\x16\x03'): protocol = "TLS/SSL"
            else: protocol = "TCP"
        elif ARP in packet: protocol = "ARP"
        elif ICMP in packet: protocol = "ICMP"
        elif TCP in packet: protocol = "TCP"
        elif UDP in packet: protocol = "UDP"
        
        if TCP in packet: info = f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet: info = f"{packet[UDP].sport} -> {packet[UDP].dport}"

        # --- 核心改动：在插入行时应用颜色标签 ---
        tag_to_apply = protocol if protocol in self.protocol_color_map else 'Unknown'
        
        item_id = self.packet_list.insert('', 'end', values=(self.packet_count, src, dst, protocol, info), tags=(tag_to_apply,))
        
        self.packets_data.append((item_id, packet))
        if len(self.packets_data) > 500:
            self.packet_list.delete(self.packets_data.pop(0)[0])
        self.packet_list.yview_moveto(1.0)

    def _update_stats_callback(self):
        self.update_stats_display()
        self._after_id = None

    def show_packet_details(self, event):
        selected_item = self.packet_list.selection()
        if not selected_item: return
            
        packet = next((pkt for item_id, pkt in self.packets_data if item_id == selected_item[0]), None)
        
        if packet:
            try:
                details = ProtocolParser(packet).parse()
                app_details = AppLayerSession(packet).parse()
                output = "--- 协议解析 ---\n" + details
                if app_details: output += "\n--- 应用层交互 ---\n" + app_details
                output += f"\n\n--- Scapy 摘要 ---\n{packet.summary()}"
            except Exception as e:
                traceback.print_exc()
                output = f"--- 解析错误 ---\n\n错误: {e}\n\n--- Scapy 摘要 ---\n{packet.summary()}"
            
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, output)
            self.detail_text.config(state=tk.DISABLED)
    
    def update_status(self, message):
        self.status_label.config(text=f"状态: {message}")