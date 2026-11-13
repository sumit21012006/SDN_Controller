#!/bin/bash
# ==============================================================================
# Terminal 1: Start Ryu SDN Controller + Detection + Mitigation
# ==============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# 1. Start Open vSwitch service if not already active
sudo service openvswitch-switch start > /dev/null 2>&1 || true

# 2. Activate Python 3.9 virtual environment
if [ -d "$HOME/ryu-env" ]; then
    source "$HOME/ryu-env/bin/activate"
else
    echo "[!] Error: ~/ryu-env not found. Please verify python3.9 virtualenv exists."
    exit 1
fi

echo "=================================================================="
echo "  🚀 Starting Ryu SDN Controller & Defense System (Port 6653)     "
echo "  Components:                                                     "
echo "   - Switch Controller (SimpleSwitch13 - OpenFlow 1.3)            "
echo "   - Telemetry Monitor (SimpleMonitor - 1s Polling)               "
echo "   - Statistical DDoS Detector (Z-score + Concentration)          "
echo "   - Automatic Flow Mod Mitigation Engine (Hardware Drop Rules)   "
echo "=================================================================="

export PYTHONPATH=.
exec ryu-manager --ofp-tcp-listen-port 6653 \
    controller/simple_switch_controller.py \
    controller/monitor.py \
    detection/ddos_detector.py \
    mitigation/mitigation_engine.py
