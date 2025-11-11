try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    TK_AVAILABLE = True
except ModuleNotFoundError:
    tk = None
    ttk = None
    scrolledtext = None
    messagebox = None
    TK_AVAILABLE = False

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

# EACH LAYERS FUNCTIONS #
def app_layer(payload: str):
    return f"HTTP/1.1 MESSAGE | PAYLOAD='{payload}'"

def pres_layer(prev: bytes):
    hdr = "[ENCODING=UTF-8][ENCRYPTION=None][COMPRESSION=None]"
    return hdr.encode("utf-8") + prev

def sess_layer(prev: bytes):
    hdr = "[SESSION_ID=12345][MODE=FULL_DUPLEX]"
    return hdr.encode("utf-8") + prev

def trans_layer(prev: bytes):
    hdr = "[SRC_PORT=5050][DST_PORT=80][SEQ=1][ACK=0]"
    return hdr.encode("utf-8") + prev

def net_layer(prev: bytes):
    hdr = "[SRC_IP=192.168.1.10][DST_IP=93.184.216.34][TTL=64][PROTO=TCP]"
    return hdr.encode("utf-8") + prev

# === SIMPLE CHECKSUM FUNCTION === #
def simple_checksum(data: bytes) -> int:
    return sum(data) % 256   # simple checksum

def dll_layer(prev: bytes, corrupt=False):
    checksum = simple_checksum(prev)
    hdr = "[DST_MAC=11:22:33:44:55:66][SRC_MAC=AA:BB:CC:DD:EE:FF][TYPE=IPv4]"
    
    # Simulate corruption by flipping one byte in the payload
    if corrupt and len(prev) > 0:
        corrupted_prev = bytearray(prev)
        # Flip the first bit of the first byte to corrupt data
        corrupted_prev[0] ^= 0x01
        prev = bytes(corrupted_prev)
    
    tlr = f"[CRC={checksum}]"  # CRC calculated on original data
    return hdr.encode("utf-8") + prev + tlr.encode("utf-8")

def phys_bits(prev: bytes):
    bits = " ".join(format(b, "08b") for b in prev)
    return "BINARY: " + bits


# Tkinter Simutator #
class OSISimulator(tk.Tk if TK_AVAILABLE else object):
    LAYERS = ["Application", "Presentation", "Session", "Transport", "Network", "Data Link", "Physical"]
    LAYER_COLORS = {
        "Application": "#FFD700",    # Gold
        "Presentation": "#00BCD4",   # Cyan
        "Session": "#9C27B0",        # Purple
        "Transport": "#FF9800",      # Orange
        "Network": "#4CAF50",        # Green
        "Data Link": "#2196F3",      # Blue
        "Physical": "#607D8B"        # Gray-Blue
    }

    LAYER_DESCRIPTIONS = {
        "Application": {
            "description": "Defines application-level protocols and formats used by end-user software.",
            "function": "Wraps your payload in an HTTP-style message with headers and a body so it can be understood at the destination.",
            "examples": "HTTP/HTTPS, FTP, SMTP, DNS, application APIs"
        },
        "Presentation": {
            "description": "Transforms the data’s representation to ensure different systems can interpret it.",
            "function": "Encodes the application message as UTF-8. If enabled, this layer would also compress or encrypt the data.",
            "examples": "Character encoding (UTF-8), compression, encryption (TLS/SSL)"
        },
        "Session": {
            "description": "Establishes, manages, and terminates sessions between communicating systems.",
            "function": "Adds a session header with an ID and dialog mode to coordinate the conversation between sender and receiver.",
            "examples": "Session tokens/IDs, dialog control (full/half duplex), synchronization"
        },
        "Transport": {
            "description": "Provides end-to-end transport services with reliability and ordering.",
            "function": "Adds TCP-like fields: source/destination ports, sequence and acknowledgement numbers to ensure reliable delivery.",
            "examples": "TCP, UDP, ports (80, 443), connection establishment, flow control"
        },
        "Network": {
            "description": "Handles logical addressing and routing across networks.",
            "function": "Adds IP-like headers: source/destination IP addresses, TTL, and protocol to route the packet.",
            "examples": "IPv4/IPv6, routers, OSPF/BGP, subnetting"
        },
        "Data Link": {
            "description": "Frames data for the local network and ensures link-level reliability.",
            "function": "Adds Ethernet-style frame headers (source/destination MAC, type) and a CRC trailer for integrity.",
            "examples": "MAC addresses, Ethernet, Wi‑Fi (802.11), CRC"
        },
        "Physical": {
            "description": "Converts frames into raw bits to send over the physical medium.",
            "function": "Outputs a preview of the bitstream that would be transmitted as electrical/optical/radio signals.",
            "examples": "Copper cables, fiber optics, RF signals, hubs, repeaters"
        }
    }
    
    # Theme colors
    DARK_BG = "#1E1E2E"
    LIGHT_TEXT = "#FFFFFF"
    ACCENT_COLOR = "#7B68EE"
    BUTTON_BG = "#3D3D5C"
    BUTTON_ACTIVE = "#5D5D8D"
    TEXT_AREA_BG = "#2A2A3A"

    def __init__(self):
        super().__init__()
        self.title("OSI Model Simulator - Sender")
        self.geometry("1100x700")
        self.resizable(True, True)
        self.configure(bg=self.DARK_BG)
        
        self.current_index = -1
        self.raw_input = ""
        self.frames_text = []
        self.frames_bytes = []
        self.clipboard_data = ""

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

        self._build_ui()

    def _build_ui(self):
        # Main container
        main_container = tk.Frame(self, bg=self.DARK_BG)
        
        # Add clipboard functionality
        self.clipboard_data = ""
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header with title
        header = tk.Frame(main_container, bg=self.DARK_BG)
        header.pack(fill=tk.X, pady=(0, 15))
        
        title = tk.Label(header, 
                        text="OSI Model Simulator - Sender", 
                        font=("Arial", 22, "bold"), 
                        bg=self.DARK_BG, 
                        fg=self.ACCENT_COLOR)
        title.pack(side=tk.LEFT)
        
        # Layer indicator
        self.layer_indicator = tk.Label(header, 
                                      text="Current Layer: None", 
                                      font=("Arial", 14), 
                                      bg=self.DARK_BG, 
                                      fg=self.LIGHT_TEXT)
        self.layer_indicator.pack(side=tk.RIGHT, padx=10)

        # Input section
        input_frame = tk.Frame(main_container, bg=self.DARK_BG)
        input_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(input_frame, 
                text="Enter Message:", 
                font=("Arial", 14), 
                bg=self.DARK_BG, 
                fg=self.LIGHT_TEXT).pack(side=tk.LEFT, padx=(0, 10))
        
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
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        # Bind Enter key to start_sim function
        self.entry.bind("<Return>", lambda event: self.start_sim())
        # Bind Enter key to trigger next_layer when input field is empty
        self.bind("<Return>", lambda event: self.next_layer() if self.btn_next["state"] == "normal" else None)
        
        # Corruption toggle
        corruption_frame = tk.Frame(main_container, bg=self.DARK_BG)
        corruption_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.simulate_corruption = tk.BooleanVar()
        corruption_check = tk.Checkbutton(corruption_frame,
                                        text="🔧 Simulate Data Corruption (for CRC failure demo)",
                                        variable=self.simulate_corruption,
                                        bg=self.DARK_BG,
                                        fg=self.LIGHT_TEXT,
                                        selectcolor=self.TEXT_AREA_BG,
                                        activebackground=self.DARK_BG,
                                        activeforeground=self.ACCENT_COLOR,
                                        font=("Arial", 11))
        corruption_check.pack(side=tk.LEFT)
        
        # Control buttons
        btn_frame = tk.Frame(main_container, bg=self.DARK_BG)
        btn_frame.pack(fill=tk.X, pady=15)

        self.btn_start = ttk.Button(btn_frame, 
                                  text="Start", 
                                  command=self.start_sim,
                                  style='TButton',
                                  width=12)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_next = ttk.Button(btn_frame, 
                                 text="Next Layer →", 
                                 command=self.next_layer, 
                                 state="disabled",
                                 style='TButton',
                                 width=14)
        self.btn_next.pack(side=tk.LEFT, padx=10)

        self.btn_reset = ttk.Button(btn_frame, 
                                  text="Reset", 
                                  command=self.reset_all,
                                  style='TButton',
                                  width=12)
        self.btn_reset.pack(side=tk.LEFT, padx=10)

        # Layer visualization
        layer_viz_frame = tk.Frame(main_container, bg=self.DARK_BG)
        layer_viz_frame.pack(fill=tk.X, pady=10)
        
        # Create layer indicators
        self.layer_indicators = []
        for i, layer in enumerate(self.LAYERS):
            indicator = tk.Frame(layer_viz_frame, 
                               width=30, 
                               height=30, 
                               bg="#555555",  # Inactive color
                               highlightthickness=1,
                               highlightbackground="#888888")
            indicator.grid(row=0, column=i, padx=5)
            indicator.pack_propagate(False)
            
            # Layer number
            num_label = tk.Label(indicator, 
                    text=f"{7-i}", 
                    font=("Arial", 10, "bold"), 
                    bg="#555555", 
                    fg=self.LIGHT_TEXT)
            num_label.pack(expand=True)
            num_label.bind("<Button-1>", lambda e, idx=i: self.on_layer_click(idx))
            indicator.bind("<Button-1>", lambda e, idx=i: self.on_layer_click(idx))
            
            # Layer name below
            name_label = tk.Label(layer_viz_frame, 
                    text=layer, 
                    font=("Arial", 8), 
                    bg=self.DARK_BG, 
                    fg=self.LIGHT_TEXT)
            name_label.grid(row=1, column=i, padx=5, pady=2)
            name_label.bind("<Button-1>", lambda e, idx=i: self.on_layer_click(idx))
            
            # Add educational tooltips
            # (Removed due to performance concerns)
            # tooltip_text = f"Layer {7-i}: {layer}\n\n{self.LAYER_DESCRIPTIONS[layer]['function']}\n\nExamples: {self.LAYER_DESCRIPTIONS[layer]['examples']}"
            # ToolTip(indicator, tooltip_text)
            # ToolTip(name_label, tooltip_text)
            
            self.layer_indicators.append(indicator)

        # Progress bar
        self.progress = ttk.Progressbar(main_container, 
                                      style="TProgressbar",
                                      length=800, 
                                      mode="determinate", 
                                      maximum=len(self.LAYERS))
        self.progress.pack(fill=tk.X, pady=15)

        # Output area
        output_frame = tk.Frame(main_container, bg=self.DARK_BG)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(output_frame, 
                text="Data Processing Output:", 
                font=("Arial", 12, "bold"), 
                bg=self.DARK_BG, 
                fg=self.LIGHT_TEXT).pack(anchor=tk.W, pady=(0, 5))
        
        self.out = scrolledtext.ScrolledText(output_frame, 
                                          wrap=tk.WORD, 
                                          width=120, 
                                          height=20,
                                          font=("Consolas", 12),
                                          bg=self.TEXT_AREA_BG,
                                          fg=self.LIGHT_TEXT,
                                          insertbackground=self.LIGHT_TEXT,
                                          relief=tk.FLAT,
                                          highlightthickness=1,
                                          highlightcolor=self.ACCENT_COLOR,
                                          highlightbackground="#555555")
        self.out.pack(fill=tk.BOTH, expand=True)

        # Copy Physical Bits button (enabled at Physical layer)
        self.copy_btn = ttk.Button(output_frame,
                                   text="Copy Physical Bits",
                                   command=self.copy_physical_bits,
                                   style='TButton',
                                   width=18)
        self.copy_btn.pack(anchor=tk.W, pady=(8, 0), padx=5)
        self.copy_btn.config(state="disabled")

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
        for layer, color in self.LAYER_COLORS.items():
            self.out.tag_configure(layer, foreground=color)
        self.out.tag_configure("highlight", background="#ffff00", foreground="#000000")

        self._write("Enter a message and press Start. Then press Next Layer to step through the OSI stack.\n", "info")

        # Footer
        footer = tk.Label(main_container, 
                        text="© OSI Model Educational Simulator", 
                        font=("Arial", 8), 
                        bg=self.DARK_BG, 
                        fg="#AAAAAA")
        footer.pack(side=tk.BOTTOM, pady=5)

    def _write(self, text: str, tag=None):
        self.out.configure(state="normal")
        if tag:
            self.out.insert(tk.END, text, tag)
        else:
            self.out.insert(tk.END, text)
        self.out.see(tk.END)
        self.out.configure(state="disabled")

    def reset_all(self, clear_entry: bool = True):
        # Clear processing state
        self.frames_text = []
        self.frames_bytes = []
        self.current_index = -1
        self.clipboard_data = ""

        # Reset UI elements
        self.btn_next.config(state="disabled")
        self.progress["value"] = 0
        self.layer_indicator.config(text="Current Layer: None")
        self.copy_btn.config(state="disabled")

        # Reset layer indicators
        for indicator in self.layer_indicators:
            indicator.config(bg="#555555")
            for child in indicator.winfo_children():
                child.config(bg="#555555")

        # Clear entry if needed
        if clear_entry:
            self.entry.delete(0, tk.END)

        # Clear output
        self.out.configure(state="normal")
        self.out.delete("1.0", tk.END)
        self.out.configure(state="disabled")

        # Provide hint text again
        self._write("Enter a message and press Start. Then press Next Layer to step through the OSI stack.\n", "info")

    # Simulation Control #
    def start_sim(self):
        msg = self.entry.get().strip()
        if not msg:
            messagebox.showwarning("Input required", "Please enter a message.")
            return

        self.reset_all(clear_entry=False)
        self.raw_input = msg
        self._write(f"Starting simulation with payload: \"{msg}\"\n", "info")
        self.btn_next.config(state="normal")
        self.current_index = -1
        self.progress["value"] = 0
        self.layer_indicator.config(text="Current Layer: None")
        
        # Reset layer indicators
        for indicator in self.layer_indicators:
            indicator.config(bg="#555555")
            for child in indicator.winfo_children():
                child.config(bg="#555555")

    def next_layer(self):
        # Simple step animation: blink current indicator before processing
        def blink(idx, cycles=3):
            if cycles <= 0:
                return
            cur = self.layer_indicators[idx]
            bg = cur.cget("bg")
            cur.config(highlightbackground=self.ACCENT_COLOR if cycles % 2 == 0 else "#888888", highlightthickness=2)
            self.after(120, lambda: blink(idx, cycles-1))
        if 0 <= self.current_index < len(self.LAYERS):
            blink(self.current_index)
        
        if self.current_index >= len(self.LAYERS) - 1:
            return

        self.current_index += 1
        layer_name = self.LAYERS[self.current_index]
        
        # Update layer indicator
        self.layer_indicator.config(text=f"Current Layer: {layer_name}")
        
        # Update layer visualization
        for i in range(len(self.layer_indicators)):
            if i <= self.current_index:
                layer_color = self.LAYER_COLORS[self.LAYERS[i]]
                self.layer_indicators[i].config(bg=layer_color)
                # Update the text color inside the indicator
                for child in self.layer_indicators[i].winfo_children():
                    child.config(bg=layer_color)
            else:
                self.layer_indicators[i].config(bg="#555555")
                # Update the text color inside the indicator
                for child in self.layer_indicators[i].winfo_children():
                    child.config(bg="#555555")

        if self.current_index == 0:
            app_text = app_layer(self.raw_input)
            app_bytes = app_text.encode("utf-8")
            self.frames_text.append(("Application", app_text))
            self.frames_bytes.append(app_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Application ===\n", "Application")
            self._write(f"Adding HTTP headers to your message\n")
        elif self.current_index == 1:
            pres_bytes = pres_layer(self.frames_bytes[-1])
            self.frames_text.append(("Presentation", "[ENCODING=UTF-8][ENCRYPTION=None][COMPRESSION=None] + previous"))
            self.frames_bytes.append(pres_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Presentation ===\n", "Presentation")
            self._write(f"Encoding data with UTF-8, no encryption or compression\n")
        elif self.current_index == 2:
            sess_bytes = sess_layer(self.frames_bytes[-1])
            self.frames_text.append(("Session", "[SESSION_ID=12345][MODE=FULL_DUPLEX] + previous"))
            self.frames_bytes.append(sess_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Session ===\n", "Session")
            self._write(f"Establishing session with ID 12345 in full-duplex mode\n")
        elif self.current_index == 3:
            trans_bytes = trans_layer(self.frames_bytes[-1])
            self.frames_text.append(("Transport", "[SRC_PORT=5050][DST_PORT=80][SEQ=1][ACK=0] + previous"))
            self.frames_bytes.append(trans_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Transport ===\n", "Transport")
            self._write(f"Adding TCP headers with source port 5050, destination port 80\n")
        elif self.current_index == 4:
            net_bytes = net_layer(self.frames_bytes[-1])
            self.frames_text.append(("Network", "[SRC_IP=192.168.1.10][DST_IP=93.184.216.34][TTL=64][PROTO=TCP] + previous"))
            self.frames_bytes.append(net_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Network ===\n", "Network")
            self._write(f"Adding IP headers with source IP 192.168.1.10, destination IP 93.184.216.34\n")
        elif self.current_index == 5:
            dll_bytes = dll_layer(self.frames_bytes[-1], corrupt=self.simulate_corruption.get())
            corruption_msg = " (⚠️ CORRUPTED)" if self.simulate_corruption.get() else ""
            self.frames_text.append(("Data Link", f"[DST/SRC MAC + TYPE] + previous + [CRC trailer]{corruption_msg}"))
            self.frames_bytes.append(dll_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Data Link ===\n", "Data Link")
            if self.simulate_corruption.get():
                self._write(f"⚠️ Adding Ethernet frame with INTENTIONAL CORRUPTION for demo\n", "error")
                self._write(f"Data corrupted but CRC calculated on original - receiver will detect mismatch!\n", "error")
            else:
                self._write(f"Adding Ethernet frame with MAC addresses and calculating CRC checksum\n")
        elif self.current_index == 6:
            frame_bytes = self.frames_bytes[-1]
            bits_preview = phys_bits(frame_bytes)
            self.frames_text.append(("Physical", bits_preview))
            self.frames_bytes.append(frame_bytes)
            self._write(f"\n=== Layer {7-self.current_index}: Physical ===\n", "Physical")
            self._write(f"Converting frame to binary bits for transmission\n")
            self._write(f"Binary representation (first 100 bits):\n{bits_preview[:100]}...\n")
            
            # Store binary data for clipboard and enable persistent button
            self.clipboard_data = bits_preview.replace("BINARY: ", "")
            self.copy_btn.config(state="normal")
            
            self.btn_next.config(state="disabled")
            self._write("\n✅ Message processing complete! Ready for transmission.\n", "success")

        self.progress["value"] = self.current_index + 1
        self.render_cumulative()

        if self.current_index == len(self.LAYERS) - 1:
            self._write("\n✅ Simulation complete! Data is ready for transmission.\n", "info")
            self.btn_next.config(state="disabled")



    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._write("\n✅ Binary data copied to clipboard!\n", "success")

    def render_cumulative(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", tk.END)

        for idx, (lname, info) in enumerate(self.frames_text):
            self.out.insert(tk.END, f"=== {idx+1}. {lname} ===\n")
            if lname == "Physical":
                self.out.insert(tk.END, info + "\n\n")
            else:
                payload_snapshot = self.frames_bytes[idx]
                snapshot_text = payload_snapshot.decode("utf-8", errors="ignore")
                if len(snapshot_text) > 240:
                    snapshot_text = snapshot_text[:240] + " ... (truncated)"
                self.out.insert(tk.END, f"{info}\n")
                self.out.insert(tk.END, f"Current PDU Snapshot: {snapshot_text}\n\n")

        self.out.configure(state="disabled")
        self.out.see(tk.END)

    def on_layer_click(self, idx: int):
        # Allow inspection of completed layers during processing
        if idx > self.current_index:
            messagebox.showinfo("Layer Details", f"Layer {idx+1} not processed yet. Complete more layers to view details.")
            return
        
        # Check if we have data for this layer
        if idx >= len(self.frames_text):
            messagebox.showinfo("Layer Details", "No data available for this layer yet.")
            return
            
        layer_name, info = self.frames_text[idx]
        
        # Add processing status to the info
        processing_status = ""
        if self.current_index < len(self.LAYERS) - 1:
            processing_status = f"\n🔄 Processing in progress... (Currently at Layer {self.current_index + 1})"
        
        if layer_name == "Physical":
            bits = self.frames_text[idx][1].replace("BINARY: ", "")
            snapshot = bits if len(bits) <= 512 else bits[:512] + " ... (truncated)"
        else:
            data = self.frames_bytes[idx]
            snapshot = data.decode("utf-8", errors="ignore")
            if len(snapshot) > 600:
                snapshot = snapshot[:600] + " ... (truncated)"
        desc = self.LAYER_DESCRIPTIONS[layer_name]["description"]
        self.show_layer_details(layer_name, desc, info + processing_status, snapshot)

    def show_layer_details(self, layer_name: str, description: str, info_text: str, snapshot_text: str):
        popup = tk.Toplevel(self)
        popup.title(f"Layer Details - {layer_name}")
        popup.configure(bg=self.DARK_BG)
        popup.transient(self)
        popup.grab_set()

        # Center the popup
        popup.update_idletasks()
        width = 800
        height = 600
        x = (popup.winfo_screenwidth() // 2) - (width // 2)
        y = (popup.winfo_screenheight() // 2) - (height // 2)
        popup.geometry(f"{width}x{height}+{x}+{y}")

        frame = tk.Frame(popup, bg=self.DARK_BG, padx=20, pady=20)
        frame.pack(fill="both", expand=True)

        # Title with color indicator and layer number
        title_frame = tk.Frame(frame, bg=self.DARK_BG)
        title_frame.pack(fill="x", pady=(0, 15))
        color_indicator = tk.Frame(title_frame, bg=self.LAYER_COLORS[layer_name], width=30, height=30)
        color_indicator.pack(side=tk.LEFT, padx=(0, 10))
        tk.Label(title_frame, text=f"{layer_name} Layer (Layer {self.LAYERS.index(layer_name)+1})", font=("Arial", 20, "bold"), fg=self.ACCENT_COLOR, bg=self.DARK_BG).pack(side=tk.LEFT)

        tk.Label(frame, text=description, font=("Arial", 12), fg=self.LIGHT_TEXT, bg=self.DARK_BG, wraplength=750, justify="left").pack(anchor=tk.W, pady=(8, 12))

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
        formatted_snapshot = self.format_snapshot_data(snapshot_text, layer_name)
        snap_box = tk.Text(snapshot_frame, height=10, bg=self.TEXT_AREA_BG, fg="#00FF00", font=("Consolas", 12), relief=tk.FLAT, highlightthickness=1, highlightcolor=self.ACCENT_COLOR, highlightbackground=self.ACCENT_COLOR)
        snap_box.pack(fill="both", expand=True, pady=(4, 0))
        snap_box.insert("1.0", formatted_snapshot)
        snap_box.configure(state="disabled")

        tk.Button(frame, text="Close", command=popup.destroy, bg=self.BUTTON_BG, fg=self.LIGHT_TEXT, font=("Arial", 10, "bold"), activebackground=self.BUTTON_ACTIVE, activeforeground=self.LIGHT_TEXT, relief="flat", padx=16, pady=6).pack(anchor=tk.E, pady=(8, 0))

    def format_snapshot_data(self, snapshot_text, layer_name):
        # Physical layer polish: show hex and binary with offsets
        if not snapshot_text:
            return "No data available at this layer."
        if layer_name == "Physical" and isinstance(snapshot_text, str):
            bits = ''.join(c for c in snapshot_text if c in '01')
            def bits_to_bytes(bit_str):
                b = []
                for i in range(0, len(bit_str) // 8 * 8, 8):
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
        headers = {
            "Data Link": "Ethernet Frame (MACs, Type, CRC):\n",
            "Network": "IP Packet (SRC/DST, TTL, PROTO):\n",
            "Transport": "TCP Segment (Ports, SEQ/ACK):\n",
            "Session": "Session Header (ID, Mode):\n",
            "Presentation": "Presentation Info (Encoding/Compression/Encryption):\n",
            "Application": "Application Message (HTTP-style):\n",
        }
        prefix = headers.get(layer_name, "")
        return prefix + snapshot_text

    def copy_physical_bits(self):
        if not getattr(self, "clipboard_data", ""):
            self._write("\n⚠️ No physical bits yet. Process to the Physical layer first.\n", "info")
            return
        self.copy_to_clipboard(self.clipboard_data)

    def export_snapshots(self):
        import json
        data = []
        for layer, preview in getattr(self, 'frames_text', []):
            entry = {
                "layer": layer,
                "preview": preview,
                "description": self.LAYER_DESCRIPTIONS.get(layer, {}).get("description", ""),
                "function": self.LAYER_DESCRIPTIONS.get(layer, {}).get("function", "")
            }
            data.append(entry)
        if not data:
            messagebox.showinfo("Export", "No snapshots to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        messagebox.showinfo("Export", f"Snapshots exported to {path}")

    def copy_logs(self):
        text = self.out.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(text)
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
    if TK_AVAILABLE:
        app = OSISimulator()
        app.mainloop()
    else:
        import argparse

        parser = argparse.ArgumentParser(description="Headless OSI Sender Simulator (no Tkinter)")
        parser.add_argument("--message", required=True, help="Payload to send")
        parser.add_argument("--print-bits", action="store_true", help="Print only the Physical layer bits (for receiver)")
        args = parser.parse_args()

        # Run the same pipeline as the GUI would, but via CLI
        app_text = app_layer(args.message)
        app_bytes = app_text.encode("utf-8")

        pres_bytes = pres_layer(app_bytes)
        sess_bytes = sess_layer(pres_bytes)
        trans_bytes = trans_layer(sess_bytes)
        net_bytes = net_layer(trans_bytes)
        dll_bytes = dll_layer(net_bytes)
        bits_preview = phys_bits(dll_bytes)

        if args.print_bits:
            print(bits_preview)
        else:
            print("=== OSI Sender (Headless) ===")
            print(f"Application: {app_text}")
            print("Presentation: [ENCODING=UTF-8][ENCRYPTION=None][COMPRESSION=None] + previous")
            print("Session: [SESSION_ID=12345][MODE=FULL_DUPLEX] + previous")
            print("Transport: [SRC_PORT=5050][DST_PORT=80][SEQ=1][ACK=0] + previous")
            print("Network: [SRC_IP=192.168.1.10][DST_IP=93.184.216.34][TTL=64][PROTO=TCP] + previous")
            print("Data Link: [DST/SRC MAC + TYPE] + previous + [CRC trailer]")
            print("Physical:")
            print(bits_preview)
