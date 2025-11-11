import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from typing import Tuple
import random
import json

class ToolTip:
    """Simple tooltip class for educational hints"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)
    
    def on_enter(self, event=None):
        x, y, _, _ = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(self.tooltip, text=self.text, 
                        background="#2A2A3A", foreground="#FFFFFF",
                        relief="solid", borderwidth=1,
                        font=("Arial", 9), wraplength=300,
                        justify="left", padx=8, pady=4)
        label.pack()
    
    def on_leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

# -------------------- Dummy Unpack Functions --------------------

def phys_to_bits(bits: str) -> bytes:
    """Convert binary string (from Physical layer) back to original bytes."""
    if bits.startswith("BINARY: "):
        bits = bits[len("BINARY: "):]  # remove "BINARY: " prefix
    # Convert space-separated binary strings into bytes
    byte_list = bits.split()
    return bytes(int(b, 2) for b in byte_list)

def simple_checksum(data: bytes) -> int:
    """Return a simple checksum by summing all bytes modulo 256"""
    return sum(data) % 256

def dll_unpack(data: bytes) -> Tuple[bytes, bool]:
    text = data.decode("utf-8", errors="ignore")

    # Extract checksum
    start = text.rfind("[CRC=")
    end = text.rfind("]")
    # Extract CRC value safely
    if "[CRC=" in text and "]" in text:
        try:
            received_crc = int(text.split("[CRC=")[-1].split("]")[0])
        except ValueError:
            received_crc = -1  # mark as invalid if parsing fails
    else:
        received_crc = -1

    # Remove only DLL headers + trailer
    payload = text.replace("[DST_MAC=11:22:33:44:55:66]", "")
    payload = payload.replace("[SRC_MAC=AA:BB:CC:DD:EE:FF]", "")
    payload = payload.replace("[TYPE=IPv4]", "")
    payload = payload.replace(f"[CRC={received_crc}]", "")

    # Recalculate checksum
    calculated_crc = simple_checksum(payload.encode())

    return payload.encode(), (received_crc == calculated_crc)


def net_unpack(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="ignore")
    text = text.replace("[SRC_IP=192.168.1.10]", "")
    text = text.replace("[DST_IP=93.184.216.34]", "")
    text = text.replace("[TTL=64]", "")
    text = text.replace("[PROTO=TCP]", "")
    return text.encode("utf-8")


def trans_unpack(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="ignore")
    text = text.replace("[SRC_PORT=5050]", "")
    text = text.replace("[DST_PORT=80]", "")
    text = text.replace("[SEQ=1]", "")
    text = text.replace("[ACK=0]", "")
    return text.encode("utf-8")


def sess_unpack(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="ignore")
    text = text.replace("[SESSION_ID=12345]", "")
    text = text.replace("[MODE=FULL_DUPLEX]", "")
    return text.encode("utf-8")


def pres_unpack(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="ignore")
    text = text.replace("[ENCODING=UTF-8]", "")
    text = text.replace("[ENCRYPTION=None]", "")
    text = text.replace("[COMPRESSION=None]", "")
    return text.encode("utf-8")


def app_unpack(data: bytes) -> str:
    text = data.decode("utf-8", errors="ignore")

    if "HTTP/1.1 MESSAGE | PAYLOAD='" in text:
        start = text.find("PAYLOAD='") + len("PAYLOAD='")
        end = text.rfind("'")
        return text[start:end]

    return text

# -------------------- Receiver App --------------------

class ReceiverApp:
    # Theme colors
    DARK_BG = "#1E1E2E"
    LIGHT_TEXT = "#FFFFFF"
    ACCENT_COLOR = "#7B68EE"
    BUTTON_BG = "#3D3D5C"
    BUTTON_ACTIVE = "#5D5D8D"
    TEXT_AREA_BG = "#2A2A3A"
    
    # Layer colors
    LAYERS = ["Physical", "Data Link", "Network", "Transport", "Session", "Presentation", "Application"]
    LAYER_COLORS = {
        "Physical": "#607D8B",      # Gray-Blue
        "Data Link": "#2196F3",     # Blue
        "Network": "#4CAF50",       # Green
        "Transport": "#FF9800",     # Orange
        "Session": "#9C27B0",       # Purple
        "Presentation": "#00BCD4",  # Cyan
        "Application": "#FFD700",   # Gold
        "error": "#FF5252",         # Red for errors
        "success": "#4CAF50",       # Green for success
        "info": "#2196F3"           # Blue for info
    }

    LAYER_DESCRIPTIONS = {
        "Physical": {
            "description": "The Physical layer is the foundation of network communication, dealing with the raw transmission of bits over a physical medium.",
            "function": "This layer converts electrical, optical, or radio signals into digital bits (1s and 0s). It defines hardware specifications like cables, connectors, voltage levels, and transmission rates. In our simulator, we receive the binary data and convert it to a format that higher layers can process.",
            "examples": "Ethernet cables, fiber optics, wireless signals, hubs, repeaters, network interface cards (NICs)"
        },
        "Data Link": {
            "description": "The Data Link layer provides reliable point-to-point data transfer between directly connected nodes.",
            "function": "This layer packages raw bits from the Physical layer into frames, handles error detection through checksums (CRC), manages flow control, and provides MAC addressing for local device identification. In our simulator, we remove the Ethernet framing and verify data integrity before passing it up.",
            "examples": "Ethernet protocols, MAC addresses, switches, bridges, Wi-Fi (802.11), error detection codes"
        },
        "Network": {
            "description": "The Network layer enables data transfer between hosts on different networks, handling logical addressing and routing.",
            "function": "This layer determines the optimal path for data to travel across multiple networks using logical addressing (IP). It handles packet forwarding, routing, and addressing. In our simulator, we strip IP headers containing source/destination addresses and other routing information.",
            "examples": "IP addresses, routers, routing protocols (OSPF, BGP), IPv4/IPv6, subnetting"
        },
        "Transport": {
            "description": "The Transport layer provides end-to-end communication services for applications, ensuring reliable data transfer.",
            "function": "This layer segments data, establishes connections (TCP) or provides connectionless service (UDP), handles flow control, error recovery, and ensures data arrives in the correct order. In our simulator, we remove TCP headers containing port numbers and sequence information.",
            "examples": "TCP, UDP, ports (80 for HTTP, 443 for HTTPS), connection establishment, flow control"
        },
        "Session": {
            "description": "The Session layer establishes, manages, and terminates connections between applications.",
            "function": "This layer handles session establishment, maintenance, and termination. It provides synchronization points for long data transfers and manages dialog control (simplex, half-duplex, full-duplex). In our simulator, we remove session identifiers and connection mode information.",
            "examples": "Session establishment, dialog control, synchronization points, RPC (Remote Procedure Call)"
        },
        "Presentation": {
            "description": "The Presentation layer translates data between the application layer and lower layers, handling data formatting and encryption.",
            "function": "This layer handles data translation, encryption, compression, and format conversion to ensure compatibility between different systems. In our simulator, we handle character encoding (UTF-8), and would manage encryption or compression if implemented.",
            "examples": "Character encoding (ASCII, Unicode), encryption (SSL/TLS), data compression, format conversion (JPEG, GIF)"
        },
        "Application": {
            "description": "The Application layer is closest to the end user, providing network services directly to applications.",
            "function": "This layer provides interfaces for applications to access network services. It includes protocols for file transfers, email, web browsing, and other end-user services. In our simulator, we extract the final HTTP-style message payload that represents the actual user data.",
            "examples": "HTTP, HTTPS, FTP, SMTP, DNS, Telnet, SSH, application APIs"
        }
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("OSI Model Simulator - Receiver")
        self.root.geometry("1100x600")
        self.root.configure(bg=self.DARK_BG)

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('TButton', 
                            background=self.BUTTON_BG, 
                            foreground=self.LIGHT_TEXT, 
                            font=('Arial', 12, 'bold'),
                            padding=8)
        self.style.map('TButton', 
                      background=[('active', self.BUTTON_ACTIVE)])
        
        self.style.configure("TProgressbar", 
                            thickness=20, 
                            troughcolor=self.DARK_BG,
                            background=self.ACCENT_COLOR)
        
        self.clipboard_data = ""

        # Main container
        main_container = tk.Frame(self.root, bg=self.DARK_BG)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header with title
        header = tk.Frame(main_container, bg=self.DARK_BG)
        header.pack(fill=tk.X, pady=(0, 15))
        
        title = tk.Label(header, 
                        text="OSI Model Simulator - Receiver", 
                        font=("Arial", 22, "bold"), 
                        bg=self.DARK_BG, 
                        fg=self.ACCENT_COLOR)
        title.pack(side=tk.LEFT)
        
        # Current layer indicator
        self.layer_indicator = tk.Label(header, 
                                      text="Current Layer: None", 
                                      font=("Arial", 14), 
                                      bg=self.DARK_BG, 
                                      fg=self.LIGHT_TEXT)
        self.layer_indicator.pack(side=tk.RIGHT, padx=10)

        # Input section with label
        input_frame = tk.Frame(main_container, bg=self.DARK_BG)
        input_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(input_frame, 
                text="Enter Physical Layer Bits:", 
                font=("Arial", 14), 
                bg=self.DARK_BG, 
                fg=self.LIGHT_TEXT).pack(anchor=tk.W, pady=(0, 5))
        
        self.entry = tk.Entry(input_frame, 
                             width=60, 
                             font=("Consolas", 14),
                             bg=self.TEXT_AREA_BG,
                             fg=self.LIGHT_TEXT,
                             insertbackground=self.LIGHT_TEXT,
                             relief=tk.FLAT,
                             highlightthickness=1,
                             highlightcolor=self.ACCENT_COLOR,
                             highlightbackground="#555555")
        self.entry.pack(fill=tk.X, ipady=5)
        
        # Bind Enter key to start_process function
        self.entry.bind("<Return>", lambda event: self.start_process())

        # Inbound corruption toggle
        self.simulate_inbound_corruption = tk.BooleanVar()
        tk.Checkbutton(input_frame,
                       text="🔧 Simulate inbound corruption (flip first bit before DLL)",
                       variable=self.simulate_inbound_corruption,
                       bg=self.DARK_BG,
                       fg=self.LIGHT_TEXT,
                       selectcolor=self.TEXT_AREA_BG,
                       activebackground=self.DARK_BG,
                       activeforeground=self.ACCENT_COLOR).pack(anchor=tk.W, pady=(6,0))

        # Buttons with improved styling
        btn_frame = tk.Frame(main_container, bg=self.DARK_BG)
        btn_frame.pack(fill=tk.X, pady=15)

        self.start_btn = ttk.Button(btn_frame, 
                                  text="Start Process", 
                                  command=self.start_process,
                                  style='TButton',
                                  width=15)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.reset_btn = ttk.Button(btn_frame, 
                                  text="Reset", 
                                  command=self.reset,
                                  style='TButton',
                                  width=10)
        self.reset_btn.pack(side=tk.LEFT, padx=10)

        # Layer visualization
        layer_viz_frame = tk.Frame(main_container, bg=self.DARK_BG)
        layer_viz_frame.pack(fill=tk.X, pady=10)
        
        # Define layers with colors
        self.layers = [
            ("Physical", "#607D8B"),      # Gray-Blue
            ("Data Link", "#2196F3"),     # Blue
            ("Network", "#4CAF50"),       # Green
            ("Transport", "#FF9800"),     # Orange
            ("Session", "#9C27B0"),       # Purple
            ("Presentation", "#00BCD4"),  # Cyan
            ("Application", "#FFD700")    # Gold
        ]
        
        # Create layer indicators
        self.layer_indicators = []
        for i, (layer_name, color) in enumerate(self.layers):
            indicator = tk.Frame(layer_viz_frame, 
                               width=30, 
                               height=30, 
                               bg="#555555",  # Inactive color
                               highlightthickness=1,
                               highlightbackground="#888888")
            indicator.grid(row=0, column=i, padx=5)
            indicator.pack_propagate(False)
            
            # Layer number (in reverse order for receiver - bottom up)
            num_label = tk.Label(indicator, 
                    text=f"{i+1}", 
                    font=("Arial", 10, "bold"), 
                    bg="#555555", 
                    fg=self.LIGHT_TEXT)
            num_label.pack(expand=True)
            num_label.bind("<Button-1>", lambda e, idx=i: self.on_layer_click(idx))
            indicator.bind("<Button-1>", lambda e, idx=i: self.on_layer_click(idx))
            
            # Layer name below
            name_label = tk.Label(layer_viz_frame, 
                    text=layer_name, 
                    font=("Arial", 8), 
                    bg=self.DARK_BG, 
                    fg=self.LIGHT_TEXT)
            name_label.grid(row=1, column=i, padx=5, pady=2)
            name_label.bind("<Button-1>", lambda e, idx=i: self.on_layer_click(idx))
            
            # Educational tooltips
            # (Removed due to performance concerns)
            # tooltip_text = f"Layer {i+1}: {layer_name}\n\n{self.LAYER_DESCRIPTIONS[layer_name]['function']}\n\nExamples: {self.LAYER_DESCRIPTIONS[layer_name]['examples']}"
            # ToolTip(indicator, tooltip_text)
            # ToolTip(name_label, tooltip_text)
            
            self.layer_indicators.append(indicator)

        # Progress Bar
        self.progress = ttk.Progressbar(main_container, 
                                      style="TProgressbar",
                                      length=800, 
                                      mode="determinate",
                                      maximum=len(self.layers))
        self.progress.pack(fill=tk.X, pady=15)

        # Output area
        output_frame = tk.Frame(main_container, bg=self.DARK_BG)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(output_frame, 
                text="Processing Output:", 
                font=("Arial", 12, "bold"), 
                bg=self.DARK_BG, 
                fg=self.LIGHT_TEXT).pack(anchor=tk.W, pady=(0, 5))
        
        self.out = tk.Text(output_frame, 
                          height=15, 
                          width=80, 
                          bg=self.TEXT_AREA_BG, 
                          fg=self.LIGHT_TEXT, 
                          font=("Consolas", 12),
                          relief=tk.FLAT,
                          highlightthickness=1,
                          highlightcolor=self.ACCENT_COLOR,
                          highlightbackground="#555555")
        self.out.pack(fill=tk.BOTH, expand=True, pady=5)
        self.out.configure(state="disabled")
        
        # Export/Log controls
        controls_frame = tk.Frame(output_frame, bg=self.DARK_BG)
        controls_frame.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(controls_frame, text="Export Snapshots",
                   command=self.export_snapshots, style='TButton', width=18).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Copy Logs",
                   command=self.copy_logs, style='TButton', width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Clear Logs",
                   command=self.clear_logs, style='TButton', width=12).pack(side=tk.LEFT, padx=5)
        tk.Label(controls_frame, text="Filter:", bg=self.DARK_BG, fg=self.LIGHT_TEXT).pack(side=tk.LEFT, padx=(16, 4))
        self.filter_var = tk.StringVar()
        tk.Entry(controls_frame, textvariable=self.filter_var, width=20,
                 bg=self.TEXT_AREA_BG, fg=self.LIGHT_TEXT, relief=tk.FLAT,
                 highlightthickness=1, highlightcolor=self.ACCENT_COLOR,
                 highlightbackground="#555555").pack(side=tk.LEFT)
        ttk.Button(controls_frame, text="Apply",
                   command=self.filter_logs, style='TButton', width=8).pack(side=tk.LEFT, padx=5)
        
        # Configure tags for colored text
        for layer_name, color in self.layers:
            self.out.tag_configure(layer_name, foreground=color)
        self.out.tag_configure("error", foreground="#FF5252")
        self.out.tag_configure("success", foreground="#4CAF50")
        self.out.tag_configure("info", foreground="#FFFFFF")
        self.out.tag_configure("highlight", background="#ffff00", foreground="#000000")
        
        # Footer
        footer = tk.Label(main_container, 
                        text="© OSI Model Educational Simulator", 
                        font=("Arial", 8), 
                        bg=self.DARK_BG, 
                        fg="#AAAAAA")
        footer.pack(side=tk.BOTTOM, pady=5)
        
        self.current_step = 0
        self.data = None
        self.ok = True

    def reset(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", tk.END)
        self.out.configure(state="disabled")
        self.entry.delete(0, tk.END)
        self.progress["value"] = 0
        self.current_step = 0
        self.data = None
        self.layer_indicator.config(text="Current Layer: None")
        self.snapshots = []
        
        # Reset layer indicators
        for indicator in self.layer_indicators:
            indicator.config(bg="#555555")
            for child in indicator.winfo_children():
                child.config(bg="#555555")

    def log(self, msg, tag=None):
        self.out.configure(state="normal")
        if tag:
            self.out.insert(tk.END, msg + "\n", (tag,))
        else:
            self.out.insert(tk.END, msg + "\n")
        self.out.see(tk.END)
        self.out.configure(state="disabled")

    def start_process(self):
        bits = self.entry.get().strip()
        if not bits:
            messagebox.showwarning("Input required", "Please paste Physical Layer bits.")
            return
 
        self.reset()
        self.data = bits
        self.log("Starting OSI Layer Processing...\n", "info")
        
        self.progress["value"] = 0
        self.current_step = 0
        self.root.after(1000, self.process_step)

    def process_step(self):
        if self.current_step >= len(self.layers):
            return

        layer, color = self.layers[self.current_step]
        self.progress["value"] = self.current_step + 1
        
        # Blink animation on current indicator
        def blink(idx, cycles=3):
            if cycles <= 0:
                return
            cur = self.layer_indicators[idx]
            cur.config(highlightbackground=self.ACCENT_COLOR if cycles % 2 == 0 else "#888888", highlightthickness=2)
            self.root.after(120, lambda: blink(idx, cycles-1))
        blink(self.current_step)
        
        # Update layer indicator
        self.layer_indicator.config(text=f"Current Layer: {layer}")
        
        # Update layer visualization
        for i in range(len(self.layer_indicators)):
            if i <= self.current_step:
                layer_color = self.layers[i][1]
                self.layer_indicators[i].config(bg=layer_color)
                # Update the text color inside the indicator
                for child in self.layer_indicators[i].winfo_children():
                    child.config(bg=layer_color)
            else:
                self.layer_indicators[i].config(bg="#555555")
                # Update the text color inside the indicator
                for child in self.layer_indicators[i].winfo_children():
                    child.config(bg="#555555")

        if layer == "Physical":
            self.data = phys_to_bits(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Physical ===", "Physical")
            self.log("Converting received bits to bytes...", "Physical")
            # Optional inbound corruption
            if self.simulate_inbound_corruption.get() and len(self.data) > 0:
                self.data = bytes([self.data[0] ^ 0x01]) + self.data[1:]
                self.log("⚠️ Inbound corruption applied: first bit flipped before Data Link.", "error")
            preview = self.data[:80].hex()
            self.snapshots.append((layer, "Convert bits to bytes for upper layers.", preview))

        elif layer == "Data Link":
            # Pre-parse CRC values from the original frame for richer details
            raw_text = self.data.decode("utf-8", errors="ignore")
            recv_crc = -1
            if "[CRC=" in raw_text and "]" in raw_text:
                try:
                    recv_crc = int(raw_text.split("[CRC=")[-1].split("]")[0])
                except ValueError:
                    recv_crc = -1
            # Build payload used for CRC calculation similar to dll_unpack
            payload_text = raw_text.replace("[DST_MAC=11:22:33:44:55:66]", "")
            payload_text = payload_text.replace("[SRC_MAC=AA:BB:CC:DD:EE:FF]", "")
            payload_text = payload_text.replace("[TYPE=IPv4]", "")
            payload_text = payload_text.replace(f"[CRC={recv_crc}]", "")
            calc_crc = simple_checksum(payload_text.encode())

            # Unpack
            self.data, self.ok = dll_unpack(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Data Link ===", "Data Link")
            if not self.ok:
                self.log("❌ CRC Check Failed! Requesting retransmission...", "error")
                # Add explicit snapshot for failure case
                preview = payload_text[:120]
                fail_info = f"CRC validation failed. Received CRC={recv_crc}, Calculated CRC={calc_crc}. Retransmission requested."
                self.snapshots.append((layer, fail_info, preview))
                # Simulate retransmission after 2 sec
                self.root.after(2000, self.retransmit)
                return
            else:
                self.log("✅ CRC Check Passed, removing Ethernet headers", "Data Link")
                preview = self.data[:120].decode("utf-8", errors="ignore")
                self.snapshots.append((layer, "Remove Ethernet framing and validate CRC.", preview))

        elif layer == "Network":
            self.data = net_unpack(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Network ===", "Network")
            self.log("Removing IP headers and checking destination address", "Network")
            preview = self.data[:120].decode("utf-8", errors="ignore")
            self.snapshots.append((layer, "Strip IP headers and validate addressing.", preview))

        elif layer == "Transport":
            self.data = trans_unpack(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Transport ===", "Transport")
            self.log("Removing TCP headers and checking port numbers", "Transport")
            preview = self.data[:120].decode("utf-8", errors="ignore")
            self.snapshots.append((layer, "Remove TCP header fields; verify ports/session.", preview))

        elif layer == "Session":
            self.data = sess_unpack(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Session ===", "Session")
            self.log("Removing Session headers and validating session ID", "Session")
            preview = self.data[:120].decode("utf-8", errors="ignore")
            self.snapshots.append((layer, "Manage session metadata and state.", preview))

        elif layer == "Presentation":
            self.data = pres_unpack(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Presentation ===", "Presentation")
            self.log("Decoding data from UTF-8, no decryption needed", "Presentation")
            preview = self.data[:120].decode("utf-8", errors="ignore")
            self.snapshots.append((layer, "Transform representation by decoding UTF-8.", preview))

        elif layer == "Application":
            msg = app_unpack(self.data)
            self.log(f"\n=== Layer {self.current_step+1}: Application ===", "Application")
            self.log(f"Extracted final message: \"{msg}\"", "Application")
            self.log("\n✅ Message received successfully!", "success")
            self.show_message_popup(msg)
            preview = msg
            self.snapshots.append((layer, "Deliver final application payload to user.", preview))

        self.current_step += 1
        self.root.after(1200, self.process_step)

    def retransmit(self):
        self.log("Retransmission received ✅", "success")
        self.ok = True
        self.log("[Data Link] ✅ CRC Check Passed on retransmission", "Data Link")
        self.current_step += 1
        self.root.after(1200, self.process_step)

    def show_message_popup(self, msg):
        popup = tk.Toplevel(self.root)
        popup.title("Final Message")
        popup.configure(bg=self.DARK_BG)
        popup.transient(self.root)
        popup.grab_set()
        
        # Center the popup
        popup.update_idletasks()
        width = 450
        height = 250
        x = (popup.winfo_screenwidth() // 2) - (width // 2)
        y = (popup.winfo_screenheight() // 2) - (height // 2)
        popup.geometry(f"{width}x{height}+{x}+{y}")
        
        content_frame = tk.Frame(popup, bg=self.DARK_BG, padx=20, pady=20)
        content_frame.pack(fill="both", expand=True)
        
        tk.Label(content_frame, text="🎉 Transmission Complete 🎉", font=("Arial", 14, "bold"), 
                 fg=self.ACCENT_COLOR, bg=self.DARK_BG).pack(pady=10)
        
        msg_frame = tk.Frame(content_frame, bg=self.TEXT_AREA_BG, padx=15, pady=15, 
                            highlightbackground=self.ACCENT_COLOR, highlightthickness=1)
        msg_frame.pack(fill="x", pady=10)
        
        tk.Label(msg_frame, text=msg, font=("Courier", 14, "bold"),
                 fg="#FFD700", bg=self.TEXT_AREA_BG, wraplength=400).pack(pady=5)
        
        tk.Button(content_frame, text="OK", command=popup.destroy, 
                 bg=self.BUTTON_BG, fg=self.LIGHT_TEXT, font=("Arial", 10, "bold"),
                 activebackground=self.BUTTON_ACTIVE, activeforeground=self.LIGHT_TEXT,
                 relief="flat", padx=20, pady=5).pack(pady=10)

    def on_layer_click(self, idx: int):
        # Allow inspection of completed layers during processing
        if idx >= self.current_step:
            messagebox.showinfo("Layer Details", f"Layer {idx+1} not processed yet. Complete more layers to view details.")
            return
            
        layer_name = self.layers[idx][0]
        desc = self.LAYER_DESCRIPTIONS[layer_name]["description"]
        
        # Find snapshot and info for this layer
        info_text = ""
        snapshot = ""
        for lname, info, snap in self.snapshots:
            if lname == layer_name:
                info_text = info
                snapshot = snap
                break
        
        # Add processing status to the info
        processing_status = ""
        if self.current_step < len(self.layers):
            processing_status = f"\n🔄 Processing in progress... (Currently at Layer {self.current_step + 1})"
            
        self.show_layer_details(layer_name, desc, info_text + processing_status, snapshot)

    def show_layer_details(self, layer_name: str, description: str, info_text: str, snapshot_text: str):
        popup = tk.Toplevel(self.root)
        popup.title(f"Layer Details - {layer_name}")
        popup.configure(bg=self.DARK_BG)
        popup.transient(self.root)
        popup.grab_set()
        
        popup.update_idletasks()
        width = 800
        height = 600
        x = (popup.winfo_screenwidth() // 2) - (width // 2)
        y = (popup.winfo_screenheight() // 2) - (height // 2)
        popup.geometry(f"{width}x{height}+{x}+{y}")
        
        frame = tk.Frame(popup, bg=self.DARK_BG, padx=20, pady=20)
        frame.pack(fill="both", expand=True)
        
        # Layer title with color indicator
        title_frame = tk.Frame(frame, bg=self.DARK_BG)
        title_frame.pack(fill="x", pady=(0, 15))
        
        color_indicator = tk.Frame(title_frame, bg=self.LAYER_COLORS[layer_name], width=30, height=30)
        color_indicator.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Label(title_frame, text=f"{layer_name} Layer (Layer {7-self.LAYERS.index(layer_name)})", 
                font=("Arial", 20, "bold"), fg=self.ACCENT_COLOR, bg=self.DARK_BG).pack(side=tk.LEFT)
        tk.Label(frame, text=description, font=("Arial", 12), fg=self.LIGHT_TEXT, bg=self.DARK_BG, wraplength=650, justify="left").pack(anchor=tk.W, pady=(8, 12))
        
        # Function section
        function_frame = tk.Frame(frame, bg=self.DARK_BG)
        function_frame.pack(fill="x", pady=(0, 15), anchor=tk.W)
        
        tk.Label(function_frame, text="Function:", font=("Arial", 14, "bold"), fg=self.ACCENT_COLOR, bg=self.DARK_BG).pack(anchor=tk.W)
        tk.Label(function_frame, text=info_text, font=("Arial", 12), fg=self.LIGHT_TEXT, bg=self.DARK_BG, wraplength=750, justify="left").pack(anchor=tk.W, pady=(4, 0))
        
        # Examples section
        examples_frame = tk.Frame(frame, bg=self.DARK_BG)
        examples_frame.pack(fill="x", pady=(0, 15), anchor=tk.W)
        
        tk.Label(examples_frame, text="Real-world Examples:", font=("Arial", 14, "bold"), fg=self.ACCENT_COLOR, bg=self.DARK_BG).pack(anchor=tk.W)
        examples_text = self.LAYER_DESCRIPTIONS[layer_name]["examples"]
        tk.Label(examples_frame, text=examples_text, font=("Arial", 12), fg=self.LIGHT_TEXT, bg=self.DARK_BG, wraplength=750, justify="left").pack(anchor=tk.W, pady=(4, 0))
        
        # Snapshot section with better formatting
        snapshot_frame = tk.Frame(frame, bg=self.DARK_BG)
        snapshot_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        tk.Label(snapshot_frame, text="Data at this Layer:", font=("Arial", 14, "bold"), fg=self.ACCENT_COLOR, bg=self.DARK_BG).pack(anchor=tk.W)
        
        # Format the snapshot for better readability
        formatted_snapshot = self.format_snapshot_data(snapshot_text, layer_name)
        
        snap_box = tk.Text(snapshot_frame, height=10, bg=self.TEXT_AREA_BG, fg="#00FF00", font=("Consolas", 12), relief=tk.FLAT, 
                          highlightthickness=1, highlightcolor=self.ACCENT_COLOR, highlightbackground=self.ACCENT_COLOR)
        snap_box.pack(fill="both", expand=True, pady=(4, 0))
        snap_box.insert("1.0", formatted_snapshot)
        snap_box.configure(state="disabled")
        
    def format_snapshot_data(self, snapshot_text, layer_name):
        """Format the snapshot data for better readability based on layer type"""
        if not snapshot_text:
            return "No data available at this layer."
            
        # Handle Physical layer: hex and binary previews with offsets
        if layer_name == "Physical":
            text = snapshot_text.strip()
            # If bits string
            if text.replace('0','').replace('1','') == '':
                bits = text
                # Group bits by bytes and build hexdump
                def bits_to_bytes(bit_str):
                    b = []
                    for i in range(0, len(bit_str)//8*8, 8):
                        b.append(int(bit_str[i:i+8], 2))
                    return bytes(b)
                b = bits_to_bytes(bits)
                lines = []
                for i in range(0, len(b), 16):
                    chunk = b[i:i+16]
                    hex_pairs = ' '.join(f"{byte:02X}" for byte in chunk)
                    lines.append(f"{i:04X}: {hex_pairs}")
                binary_groups = ' '.join(bits[j:j+8] for j in range(0, len(bits), 8))
                return (
                    "Hex preview (offsets):\n" + "\n".join(lines) +
                    "\n\nBinary stream (8-bit groups):\n" + binary_groups
                )
            else:
                # Assume hex string; group and add offsets
                hexstr = ''.join(c for c in text if c.upper() in '0123456789ABCDEF')
                # Make bytes
                b = bytes.fromhex(hexstr) if hexstr else b''
                lines = []
                for i in range(0, len(b), 16):
                    chunk = b[i:i+16]
                    hex_pairs = ' '.join(f"{byte:02X}" for byte in chunk)
                    lines.append(f"{i:04X}: {hex_pairs}")
                return "Hex preview (offsets):\n" + "\n".join(lines)
            
        # Format data with headers for other layers
        if layer_name == "Data Link":
            return f"Ethernet Frame:\n{snapshot_text}"
        elif layer_name == "Network":
            return f"IP Packet:\n{snapshot_text}"
        elif layer_name == "Transport":
            return f"TCP Segment:\n{snapshot_text}"
        elif layer_name == "Session":
            return f"Session Data:\n{snapshot_text}"
        elif layer_name == "Presentation":
            return f"Presentation Data:\n{snapshot_text}"
        elif layer_name == "Application":
            return f"Application Data (Final Message):\n{snapshot_text}"
            
        return snapshot_text

    def export_snapshots(self):
        if not hasattr(self, 'snapshots') or not self.snapshots:
            messagebox.showinfo("Export", "No snapshots to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
        if not path:
            return
        data = []
        for layer, info, preview in self.snapshots:
            data.append({"layer": layer, "info": info, "preview": preview})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        messagebox.showinfo("Export", f"Snapshots exported to {path}")

    def copy_logs(self):
        self.out.configure(state="normal")
        text = self.out.get("1.0", tk.END)
        self.out.configure(state="disabled")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copy", "Logs copied to clipboard")

    def clear_logs(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", tk.END)
        self.out.configure(state="disabled")

    def filter_logs(self):
        query = self.filter_var.get().strip()
        self.out.configure(state="normal")
        self.out.tag_remove("highlight", "1.0", tk.END)
        if query:
            idx = "1.0"
            while True:
                idx = self.out.search(query, idx, nocase=True, stopindex=tk.END)
                if not idx:
                    break
                end = f"{idx}+{len(query)}c"
                self.out.tag_add("highlight", idx, end)
                idx = end
        self.out.configure(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()
