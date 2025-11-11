import tkinter as tk
from tkinter import ttk
import subprocess
import os

def open_sender():
    sender_path = os.path.join(os.path.dirname(__file__), "sender.py")
    subprocess.Popen(["python3", sender_path])

def open_receiver():
    receiver_path = os.path.join(os.path.dirname(__file__), "receiver.py")
    subprocess.Popen(["python3", receiver_path])

# Define colors
DARK_BG = "#1E1E2E"
LIGHT_TEXT = "#FFFFFF"
ACCENT_COLOR = "#7B68EE"  # Medium slate blue
BUTTON_BG = "#3D3D5C"
BUTTON_HOVER = "#4A4A6A"
BUTTON_ACTIVE = "#5D5D8D"

# MAIN CONTROL WINDOW
root = tk.Tk()
root.title("OSI Model Simulator")
root.geometry("500x500")
root.resizable(False, False)
root.configure(bg=DARK_BG)

# Custom style for buttons
style = ttk.Style()
style.theme_use('default')
style.configure('TButton', 
                background=BUTTON_BG, 
                foreground=LIGHT_TEXT, 
                font=('Arial', 12, 'bold'),
                padding=10,
                width=20)
style.map('TButton', 
          background=[('active', BUTTON_ACTIVE), ('hover', BUTTON_HOVER)])

# Header with OSI model image (text-based ASCII art)
header_frame = tk.Frame(root, bg=DARK_BG)
header_frame.pack(pady=20)

title = tk.Label(header_frame, 
                text="OSI Model Simulator", 
                font=("Arial", 24, "bold"), 
                bg=DARK_BG, 
                fg=ACCENT_COLOR)
title.pack()

# Subtitle
subtitle = tk.Label(header_frame, 
                   text="Explore the 7 Layers of the OSI Model", 
                   font=("Arial", 12), 
                   bg=DARK_BG, 
                   fg=LIGHT_TEXT)
subtitle.pack(pady=5)

# ASCII art representation of OSI layers
osi_art = """
┌───────────────────┐
│  7. Application   │
├───────────────────┤
│  6. Presentation  │
├───────────────────┤
│    5. Session     │
├───────────────────┤
│   4. Transport    │
├───────────────────┤
│    3. Network     │
├───────────────────┤
│   2. Data Link    │
├───────────────────┤
│   1. Physical     │
└───────────────────┘
"""

art_label = tk.Label(root, 
                    text=osi_art, 
                    font=("Courier New", 10), 
                    bg=DARK_BG, 
                    fg=ACCENT_COLOR,
                    justify="left")
art_label.pack(pady=10)

# Button frame
button_frame = tk.Frame(root, bg=DARK_BG)
button_frame.pack(pady=15)

# Buttons with improved styling
btn_sender = ttk.Button(button_frame, 
                       text="Open Sender", 
                       command=open_sender,
                       style='TButton')
btn_sender.grid(row=0, column=0, padx=10, pady=10)

btn_receiver = ttk.Button(button_frame, 
                         text="Open Receiver", 
                         command=open_receiver,
                         style='TButton')
btn_receiver.grid(row=0, column=1, padx=10, pady=10)

# Exit button
quit_btn = ttk.Button(root, 
                     text="Exit", 
                     command=root.quit,
                     style='TButton',
                     width=10)
quit_btn.pack(pady=15)

# Footer
footer = tk.Label(root, 
                 text="© OSI Model Educational Simulator", 
                 font=("Arial", 8), 
                 bg=DARK_BG, 
                 fg="#AAAAAA")
footer.pack(side=tk.BOTTOM, pady=5)

root.mainloop()
