# 🧠 OSI Model Simulator (Tkinter)

An interactive Python (Tkinter) project that visualizes how data travels through the 7 layers of the OSI Model, from Sender → Receiver.
It demonstrates encapsulation, decapsulation, CRC error detection, and retransmission — all through a clean step-by-step GUI simulation.

---

## 🚀 Key Features
- 🧩 Full OSI Layer Flow – Step through all 7 layers, both sender and receiver sides.
- ⚙️ Encapsulation & Decapsulation – Each layer adds/removes headers just like in real networking.
- 🧠 Checksum (CRC) – Detects transmission errors automatically.
- 🔁 Retransmission Simulation – If data is corrupted, simulator auto “resends” the correct data.
- 🎯 Step Animations – Visual feedback as data moves through layers.
- 💡 Realistic Headers – MAC, IP, Port, Session ID, Encoding, etc.
- 🖥️ Dark UI with Clean Layout – Tkinter interface optimized for teaching clarity.
- 🧾 Educational Focus – Ideal for Computer Networks lab demonstrations.

---

## ⚡ Quick Start

### 🧩 Requirements
- Python 3.10+
- Tkinter (comes built-in with Python — no extra install needed)

### ▶️ Run the Simulator
```bash
python3 main.py
```

### 🧠 Sender Side
- Enter a message (e.g., "Hello").
- Click `Start` → then click `Next Layer` to move through OSI layers.
- The simulator shows encapsulation at each step (Application → Physical).
- The Physical layer outputs the binary bits of the message.

### 🧠 Receiver Side
- Copy the Physical layer bits and paste them into the receiver.
- Click `Start Process` to begin decapsulation (Physical → Application).
- If CRC fails, the simulator prints “Retransmission Requested” and auto-recovers the correct data.
- Finally, the original message appears at the receiver.

---

## 📊 Physical Layer Preview
Shows raw data as binary bits, grouped in 8-bit chunks for readability:

```text
BINARY: 01001000 01100101 01101100 01101100 01101111
```

This represents the ASCII bytes for the message HELLO.

---

## 🧱 Project Structure

```bash
OSI_Model_Simulator/
├── main.py        # Main control panel (launches sender/receiver)
├── sender.py      # Sender-side OSI simulation
├── receiver.py    # Receiver-side OSI simulation
└── layers/        # Modularized layer implementations
    ├── application.py
    ├── presentation.py
    ├── session.py
    ├── transport.py
    ├── network.py
    ├── datalink.py
    └── physical.py
```

---

## 🧩 OSI Layers Simulated

| Layer       | Operation                                 |
|-------------|--------------------------------------------|
| Application | Adds HTTP-like protocol info               |
| Presentation| Adds encoding/compression/encryption flags |
| Session     | Adds Session ID & mode                     |
| Transport   | Adds source/destination ports, seq & ack   |
| Network     | Adds source/destination IP and TTL         |
| Data Link   | Adds MAC addresses + CRC trailer           |
| Physical    | Converts the entire frame into binary bits |

---

## 🧰 Tech Stack

| Component | Technology Used           |
|-----------|---------------------------|
| Language  | Python 3                  |
| GUI       | Tkinter                   |
| Logic     | OSI Simulation + CRC      |
| OS Support| Windows / macOS / Linux   |

---

## 🎓 Learning Outcome
- Visualize how data is encapsulated and decapsulated across OSI layers.
- Understand headers/trailers, addressing (MAC/IP/ports), and payload flow.
- Learn checksum-based error detection and retransmission (ARQ) practically.

---

## 💡 Future Enhancements (Roadmap)
- Add UDP mode (unreliable, no retransmission).
- Add noise simulator (configurable bit error rate).
- Export logs/snapshots as Markdown/HTML or a small report.
- Add an animated visual link showing packet travel between Sender ↔ Receiver.
- Accessibility: larger fonts, theme toggle (light/dark).

---

## 👥 Team Members

| Name        | Role                                  | GitHub                  |
|-------------|---------------------------------------|-------------------------|
| Daksh Goel  | Project Lead — UI & Sender logic      | (add your link)         |
| Rachit Yadav| Receiver logic, CRC & testing         | RachitYadavHsr          |
| [Third]     | Documentation & Presentation          | (add name/link)         |

---

## 📝 Notes for the Instructor / Reviewer
- The retransmission behavior in this demo is an educational simulation (sender/receiver run in the same environment). Retransmission is simulated automatically for clarity — the sender uses stored original frame to demonstrate ARQ without external networking.
- All headers and CRC values are human-readable strings for teaching clarity.

---

## 🏁 Closing Line
“Our OSI Model Simulator makes theoretical networking concepts interactive and practical by showing—step-by-step—how data is packaged, transmitted, verified, and recovered.”