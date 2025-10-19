import tkinter as tk
from gui import SnifferGUI

if __name__ == "__main__":
    # 创建主窗口
    root = tk.Tk()
    
    # 实例化 GUI 应用
    app = SnifferGUI(root)
    
    # 启动事件循环
    root.mainloop()