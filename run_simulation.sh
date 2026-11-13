#!/bin/bash
# ==============================================================================
# Terminal 2: Clean and Run Mininet Network Topology & DDoS Attack Test
# ==============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=================================================================="
echo "  🧹 Cleaning previous Mininet interfaces & bridges...            "
sudo ovs-vsctl --if-exists del-br s1
sudo ovs-vsctl --if-exists del-br s2
sudo pkill -9 -f "http.server" 2>/dev/null || true
sudo pkill -9 -f "hping3" 2>/dev/null || true

echo ""
echo "=================================================================="
echo "  🌐 Launching Mininet Virtual SDN Network...                     "
echo "  Topology:                                                       "
echo "   - Switches: s1 (Clients: 10.0.0.1 - 3)                         "
echo "               s2 (Attackers: 10.0.0.100 - 101, Server: 10.0.0.200)"
echo "   - Phase 1: HTTP Web Server starts on server1:80                "
echo "   - Phase 2: 15s Normal Web Traffic Baseline                     "
echo "   - Phase 3: PingAll Connectivity Validation                     "
echo "   - Phase 4: Controlled SYN Flood Attack (attacker1 -> server1)  "
echo "=================================================================="
sudo python3 topology/sdn_topo.py --controller remote --test-attack
