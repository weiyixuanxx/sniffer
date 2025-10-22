import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from gui import SnifferGUI

"""
    主函数。
    直接点击该文件运行即可。
"""
if __name__ == "__main__":
    root = ttk.Window()
    style = ttk.Style(theme='solar')
    app = SnifferGUI(root)
    root.mainloop()