# DeepInsight - Deep Packet Inspection & Traffic Analysis Dashboard

DeepInsight is a modern, light-themed web-based packet analyzer and Deep Packet Inspection (DPI) dashboard. It provides network traffic analysis, flow classification, packet-level inspection, and policy-based blocking in a clean 3-column interface.

Built for out-of-the-box compatibility on Windows systems, the dashboard runs on a native Python 3 port of the DPI engine paired with a Node.js/Express API backend.

---

## Key Features

- **Interactive Dashboard**: Modern 3-column layout with animated ring progress indicators, real-time statistics cards, and traffic summaries.
- **DPI Flow Classification**: Tracks bidirectional connection flows using 5-tuple matching and classifies application traffic (YouTube, Spotify, Netflix, GitHub, etc.) by extracting SNI from TLS Client Hello handshakes and Host headers from plain HTTP requests.
- **Traffic Capture Simulator**: Synthesizes mock `.pcap` traces on-the-fly with configurable baseline (DNS, HTTP, Blocked IP) and application traffic mix.
- **Packet Hex Inspector**: Expand any connection flow to view its packet sequence (timestamps, direction, sizes) and raw payload bytes formatted as a hex dump with printable ASCII.
- **Active Blocking Policy**: Manage rules to block traffic by Source IP, Application Class, or Domain Substring. The engine applies rules in real-time, filters the capture, and allows downloading the filtered `.pcap` file.

---

## Quick Start

### Prerequisites
- Node.js (v18+)
- Python (v3.8+)

### Running Locally

1. Clone the repository.
2. On Windows, double-click `run_dashboard.bat`, or run manually:
   ```bash
   npm install
   npm start
   ```
3. Open your browser and go to `http://localhost:3000`.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| DPI Core | Python 3 (struct, socket) |
| Backend API | Node.js, Express, Multer |
| Frontend | HTML5, Vanilla CSS, Vanilla JS |
| Charts | Chart.js |
| Fonts | Google Fonts (Inter, Outfit) |

---

## Author

Moksh Jain - [github.com/Moksh-jain-07](https://github.com/Moksh-jain-07)
