import threading
from scapy.all import sniff, get_working_if

class PacketSniffer:
    """
    负责启动和停止数据包嗅探的后台线程。
    """

    def __init__(self, gui_callback):
        self.gui = gui_callback
        self.sniffing = False
        self.thread = None

    def start(self, filter_exp):
        """启动嗅探线程。"""
        if not self.sniffing:
            self.sniffing = True
            # 使用 daemon=True 确保主程序退出时线程也会退出
            self.thread = threading.Thread(target=self._sniff_loop, args=(filter_exp,), daemon=True)
            self.thread.start()
            self.gui.update_status("嗅探中...")

    def stop(self):
        """停止嗅探线程。"""
        self.sniffing = False
        # 等待线程结束
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        self.gui.update_status("已停止")

    def _sniff_loop(self, filter_exp):
        """嗅探循环，传递给线程执行。"""
        try:
            # stop_filter 会在每个数据包后检查是否应该停止
            sniff(prn=self.gui.display_packet, filter=filter_exp, stop_filter=lambda x: not self.sniffing, iface=get_working_if())
        except Exception as e:
            # 处理可能的权限错误等问题
            self.gui.update_status(f"错误: {e}")