# OSI Model Simulator (Tkinter)

An interactive Tkinter-based simulator that lets you step a message through the OSI model from Sender to Receiver. See how data transforms across layers, visualize Physical layer bits in hex/binary, toggle corruption, and export snapshots for teaching or debugging.

## Key Features
- Step-through OSI flow for both Sender and Receiver
- Mid-process inspection popups with status banners (success/fail)
- Physical layer preview with grouped hex and binary stream
- Export snapshots to a text file
- Logging controls: copy, clear, and filter
- Filter highlighting uses bright yellow background with black text for visibility
- Inbound/Outbound corruption toggles (simulate errors)
- Simple blinking step animation on active layer indicators

## Quick Start
- Requirements: Python 3.10+ (macOS/Windows/Linux), Tkinter (bundled with Python)
- No external dependencies needed

### Run the simulator
```
python3 main.py
```
- A control window opens with buttons to launch Sender and Receiver.
- Use the Sender to enter a message and step through layers.
- Launch the Receiver to process the inbound data and verify integrity.

## How to Use
- Start: Enter text in Sender and press `Start`.
- Next Layer: Use `Next Layer` to step through OSI layers.
- Corruption:
  - Sender: Toggle outbound corruption to introduce bit errors.
  - Receiver: Toggle inbound corruption for testing error handling.
- Export Snapshots: Click `Export` to save a detailed report of all layer snapshots.
- Logs:
  - `Copy` copies the visible logs to your clipboard.
  - `Clear` clears the log area.
  - `Filter` highlights all occurrences of the entered term.
    - Case-insensitive substring search.
    - Highlights in yellow with black text.
    - It does not hide lines; it only highlights matches.

## Physical Layer Preview
The Physical layer shows:
- Hexadecimal bytes grouped for readability
- Binary stream grouped in 8-bit chunks
- Byte offsets to help relate positions

Example (illustrative):
```
Offset  Hex                        Binary
0000    48 65 6C 6C 6F             01001000 01100101 01101100 01101100 01101111
```

## Project Structure
```
OSI_Model_Simulator/
├── main.py        # Entry point: opens control window, spawns Sender/Receiver
├── sender.py      # Sender UI, layer stepping, export/logging, corruption toggle
├── receiver.py    # Receiver UI, processing steps, export/logging, corruption toggle
└── layers/        # OSI layer modules (Application → Physical)
    ├── application.py
    ├── presentation.py
    ├── session.py
    ├── transport.py
    ├── network.py
    ├── datalink.py
    └── physical.py
```

## Design Notes
- Each OSI layer module encapsulates its transform and snapshot data.
- UI maintains a log `Text` widget with tags per layer and a `highlight` tag for filtering.
- Export collates snapshots across layers with human-friendly formatting.

## Contributing
- Fork and open a PR
- Keep changes minimal and focused; follow the existing style
- If adding features, update this README

## Roadmap Ideas
- Theme toggle (light/dark)
- Larger font and accessibility tweaks
- Rich snapshot exports (Markdown/HTML)
- Pre-built demo flows for teaching