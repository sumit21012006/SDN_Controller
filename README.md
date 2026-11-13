# 🛡️ SDN-Based DDoS Detection and Automatic Mitigation Framework

An end-to-end Software-Defined Networking (SDN) security system built with **Ryu OpenFlow 1.3 Controller** and **Mininet Network Emulator**. The system features real-time traffic polling, dynamic 15-second baseline statistical learning, a 100-point multi-feature anomaly scoring engine, and a 3-cycle persistence state machine for precise DDoS detection with zero false positives.

---

## 📐 Network Topology Architecture

```text
               +-------------------------------------------------------+
               |             Ryu SDN Remote Controller                 |
               |                                                       |
               |  [L2 Learning Switch]      [Periodic Traffic Monitor] |
               |                                       ||              |
               |                                       \/              |
               |                        [Statistical DDoS Detector]    |
               |                        - 15s Warm-up Baseline (μ, σ)  |
               |                        - 100-pt Anomaly Score         |
               |                        - 3-Interval Persistence       |
               |                        - CSV & Log Alert Exporter     |
               +-------------------------------------------------------+
                                    ||             ||
                           OpenFlow ||             || OpenFlow
                           Protocol ||             || Protocol
                                    \/             \/
                           [Switch s1] <=========> [Switch s2]
                            /   |   \               /    |                               /    |    \             /     |                           client1 client2 client3 attacker1 attacker2 server1
                     (10.0.0.1)(10.0.0.2)(10.0.0.3)(10.0.0.100)(10.0.0.101)(10.0.0.200)
```

- **Protected Target (`server1`)**: `IP: 10.0.0.200` | `MAC: 00:00:00:00:00:fe`
- **Known Attack Hosts**: `attacker1` (`10.0.0.100`), `attacker2` (`10.0.0.101`)
- **Legitimate Clients**: `client1` (`10.0.0.1`), `client2` (`10.0.0.2`), `client3` (`10.0.0.3`)

---

## 📂 Repository Structure

```text
SDN-DDoS-Detection-and-Mitigation/
├── topology/
│   └── sdn_topo.py                   # Mininet OpenFlow 1.3 topology script & automated test harness
├── controller/
│   ├── simple_switch_controller.py   # Ryu OpenFlow 1.3 L2 Learning Switch (MAC learning & flow setup)
│   └── monitor.py                    # Periodic 1s traffic poller (PPS/BPS delta rate calculations)
├── detection/
│   └── ddos_detector.py              # Statistical & Rule-Based Multi-Feature DDoS Detection Engine
├── mitigation/                       # [Phase 5] OpenFlow 1.3 DROP flow-mod mitigation engine
│   ├── __init__.py
│   └── mitigation_engine.py
├── logs/
│   ├── traffic/                      # Real-time CSV logs for port and flow statistics
│   ├── detection/                    # Detection event CSV logs and human-readable event traces
│   └── mitigation/                   # Mitigation event logs and active blocklists
├── README.md                         # Project documentation and user guide
└── setup_phase4.py                   # Setup script for Phase 4 detector initialization
```

---

## 📊 Project Completion Matrix

| Phase | Description | Key Modules | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Mininet Topology Setup | `topology/sdn_topo.py` | ✅ **Completed** |
| **Phase 2** | Ryu L2 Learning Controller | `controller/simple_switch_controller.py` | ✅ **Completed** |
| **Phase 3** | Periodic Traffic Monitoring | `controller/monitor.py` | ✅ **Completed** |
| **Phase 4** | Statistical DDoS Detection Engine | `detection/ddos_detector.py` | ✅ **Completed** |
| **Phase 5** | Automatic DDoS Mitigation Engine | `mitigation/mitigation_engine.py` | ⏳ **In Progress** |

---

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
