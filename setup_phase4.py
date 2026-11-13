import os

det_code = r'''#!/usr/bin/env python3
import os, csv, time, math, datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

SERVER1_IP = "10.0.0.200"
SERVER1_MAC = "00:00:00:00:00:fe"

class DDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    DEFAULT_BASELINE_DURATION = 15
    DEFAULT_PERSISTENCE_INTERVALS = 3
    DEFAULT_SUSPICION_THRESHOLD = 60

    def __init__(self, *args, **kwargs):
        super(DDoSDetector, self).__init__(*args, **kwargs)
        self.baseline_duration = kwargs.get('baseline_duration', 15)
        self.persistence_intervals = kwargs.get('persistence_intervals', 3)
        self.suspicion_threshold = kwargs.get('suspicion_threshold', 60)
        self.start_time = time.time()
        self.is_baseline_complete = False
        self.baseline_samples = {'packet_rate': [], 'byte_rate': [], 'active_flows': []}
        self.baseline_stats = {'mean_pps': 0.0, 'std_pps': 0.0, 'mean_bps': 0.0, 'std_bps': 0.0, 'mean_flows': 0.0, 'std_flows': 0.0, 'max_flows': 0}
        self.current_state = "BASELINE_COLLECTION"
        self.dp_consecutive_suspicious = {}
        self.log_dir = os.path.join(os.path.expanduser("~"), "CN_CP", "logs", "detection")
        os.makedirs(self.log_dir, exist_ok=True)
        self.csv_path = os.path.join(self.log_dir, "detection_events.csv")
        self.log_path = os.path.join(self.log_dir, "detection.log")
        self._init_files()
        self.logger.info("==================================================")
        self.logger.info("   Ryu Statistical DDoS Detection Engine Initialized")
        self.logger.info("   Target Server: IP=%s, MAC=%s" % (SERVER1_IP, SERVER1_MAC))
        self.logger.info("   Baseline Warm-Up Duration: %ds" % self.baseline_duration)
        self.logger.info("   Suspicion Score Threshold: %d / 100" % self.suspicion_threshold)
        self.logger.info("   Persistence Requirement: %d intervals" % self.persistence_intervals)
        self.logger.info("==================================================")

    def _init_files(self):
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, 'w', newline='') as f:
                csv.writer(f).writerow(['timestamp','iso_time','server_ip','packet_rate','byte_rate','active_flows','unique_sources','traffic_concentration','suspicion_score','consecutive_suspicious','detection_status','reason'])

    def _log_event(self, msg):
        self.logger.info(msg)
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_path, 'a') as f:
            f.write("[%s] %s\n" % (now_str, msg))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        now = time.time()
        iso_str = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')

        server_flows = []
        source_packets = {}
        total_server_pkts = 0
        total_server_bytes = 0

        for stat in body:
            priority = stat.priority
            pkts = stat.packet_count
            bytes_cnt = stat.byte_count
            eth_dst = str(stat.match['eth_dst']).lower() if 'eth_dst' in stat.match else 'any'
            eth_src = str(stat.match['eth_src']).lower() if 'eth_src' in stat.match else 'any'
            if priority == 1 and eth_dst == SERVER1_MAC.lower() and eth_src != 'any':
                server_flows.append(stat)
                source_packets[eth_src] = source_packets.get(eth_src, 0) + pkts
                total_server_pkts += pkts
                total_server_bytes += bytes_cnt

        if not server_flows and total_server_pkts == 0:
            return

        active_flows = len(server_flows)
        unique_sources = len(source_packets)
        traffic_concentration = (max(source_packets.values()) / total_server_pkts * 100.0) if (total_server_pkts > 0 and source_packets) else 0.0
        dur_list = [s.duration_sec for s in server_flows]
        total_dur = max(dur_list) if dur_list else 1.0
        total_dur = max(1.0, float(total_dur))
        packet_rate = total_server_pkts / total_dur
        byte_rate = total_server_bytes / total_dur

        elapsed = now - self.start_time
        if elapsed < self.baseline_duration and not self.is_baseline_complete:
            self.current_state = "BASELINE_COLLECTION"
            self.baseline_samples['packet_rate'].append(packet_rate)
            self.baseline_samples['byte_rate'].append(byte_rate)
            self.baseline_samples['active_flows'].append(active_flows)
            self._log_event("[BASELINE WARM-UP %.1f/%ds] Samples=%d | Server PPS=%.1f" % (elapsed, self.baseline_duration, len(self.baseline_samples['packet_rate']), packet_rate))
            self._write_csv(now, iso_str, packet_rate, byte_rate, active_flows, unique_sources, traffic_concentration, 0, "BASELINE_COLLECTION", "Collecting baseline samples")
            return

        if not self.is_baseline_complete:
            self.is_baseline_complete = True
            self._compute_baseline_statistics()
            self._log_event("✅ Baseline Collection Complete! Transitioning to ACTIVE DETECTION.")

        score_pps = 30 if (packet_rate > (self.baseline_stats['mean_pps'] + 3 * self.baseline_stats['std_pps']) or packet_rate > 50.0) else 0
        score_bps = 25 if (byte_rate > (self.baseline_stats['mean_bps'] + 3 * self.baseline_stats['std_bps']) or (byte_rate * 8) > 200000.0) else 0
        score_flows = 20 if (active_flows > max(self.baseline_stats['max_flows'] + 2, self.baseline_stats['mean_flows'] + 2)) else 0
        score_conc = 25 if (traffic_concentration > 70.0 and total_server_pkts > 20) else 0

        reasons = []
        if score_pps: reasons.append("PacketRateHigh(%.1f > thresh %.1f)" % (packet_rate, self.baseline_stats['mean_pps'] + 3 * self.baseline_stats['std_pps']))
        if score_bps: reasons.append("ByteRateHigh(%.1fKbps)" % (byte_rate*8/1000.0))
        if score_flows: reasons.append("FlowCountHigh(%d)" % active_flows)
        if score_conc: reasons.append("HighConcentration(%.1f%%)" % traffic_concentration)

        total_suspicion_score = score_pps + score_bps + score_flows + score_conc

        if dpid not in self.dp_consecutive_suspicious:
            self.dp_consecutive_suspicious[dpid] = 0

        if total_suspicion_score >= self.suspicion_threshold:
            self.dp_consecutive_suspicious[dpid] += 1
            if self.dp_consecutive_suspicious[dpid] >= self.persistence_intervals:
                self.current_state = "DDOS_DETECTED"
            else:
                self.current_state = "SUSPICIOUS"
        else:
            self.dp_consecutive_suspicious[dpid] = 0
            self.current_state = "NORMAL"

        consec = self.dp_consecutive_suspicious[dpid]
        reason_str = "; ".join(reasons) if reasons else "Traffic within normal baseline ranges"

        self._log_event("[DETECTION STATE: %s] Score=%d/100 (Switch dpid=%d, Persistence=%d/%d) | Reason: %s" % (self.current_state, total_suspicion_score, dpid, consec, self.persistence_intervals, reason_str))
        self._write_csv(now, iso_str, packet_rate, byte_rate, active_flows, unique_sources, traffic_concentration, total_suspicion_score, self.current_state, reason_str)

    def _compute_baseline_statistics(self):
        for metric in ['packet_rate', 'byte_rate', 'active_flows']:
            samples = self.baseline_samples[metric]
            if samples:
                n = len(samples)
                mean = sum(samples) / n
                variance = sum((x - mean) ** 2 for x in samples) / n
                std = math.sqrt(variance)
            else:
                mean, std = 0.0, 0.0

            if metric == 'packet_rate':
                self.baseline_stats['mean_pps'] = mean
                self.baseline_stats['std_pps'] = max(std, 2.0)
            elif metric == 'byte_rate':
                self.baseline_stats['mean_bps'] = mean
                self.baseline_stats['std_bps'] = max(std, 200.0)
            elif metric == 'active_flows':
                self.baseline_stats['mean_flows'] = mean
                self.baseline_stats['std_flows'] = std
                self.baseline_stats['max_flows'] = max(samples) if samples else 0

        self._log_event("📊 Baseline Stats Computed: PPS(mean=%.1f, std=%.1f) | BPS(mean=%.0f, std=%.0f) | Flows(max=%d)" % (self.baseline_stats['mean_pps'], self.baseline_stats['std_pps'], self.baseline_stats['mean_bps']*8, self.baseline_stats['std_bps']*8, self.baseline_stats['max_flows']))

    def _write_csv(self, now, iso_str, pps, bps, flows, sources, conc, score, status, reason):
        with open(self.csv_path, 'a', newline='') as f:
            writer = csv.writer(f)
            consec_val = max(self.dp_consecutive_suspicious.values()) if self.dp_consecutive_suspicious else 0
            writer.writerow([f"{now:.3f}", iso_str, SERVER1_IP, f"{pps:.2f}", f"{bps*8:.2f}", flows, sources, f"{conc:.2f}", score, consec_val, status, reason])
'''

topo_code = r'''#!/usr/bin/env python3
import sys, time, argparse
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class SDNDDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        client1 = self.addHost('client1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        client2 = self.addHost('client2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        client3 = self.addHost('client3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        attacker1 = self.addHost('attacker1', ip='10.0.0.100/24', mac='00:00:00:00:00:A1')
        attacker2 = self.addHost('attacker2', ip='10.0.0.101/24', mac='00:00:00:00:00:A2')
        server1 = self.addHost('server1', ip='10.0.0.200/24', mac='00:00:00:00:00:FE')
        self.addLink(client1, s1)
        self.addLink(client2, s1)
        self.addLink(client3, s1)
        self.addLink(attacker1, s2)
        self.addLink(attacker2, s2)
        self.addLink(server1, s2)
        self.addLink(s1, s2)

def run_topology(controller_type='default', controller_ip='127.0.0.1', controller_port=6653, test_normal=False, test_attack=False):
    topo = SDNDDoSTopo()
    if controller_type == 'remote':
        info("*** Using Remote Controller (Ryu) at %s:%s\n" % (controller_ip, controller_port))
        controller = lambda name: RemoteController(name, ip=controller_ip, port=controller_port)
        net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink, build=True)
    else:
        info("*** Using Standalone OVS Mode\n")
        net = Mininet(topo=topo, switch=OVSSwitch, controller=None, link=TCLink, build=True)
    net.start()
    for switch in net.switches:
        switch.cmd('ovs-vsctl set bridge %s protocols=OpenFlow13' % switch.name)
        if controller_type != 'remote':
            switch.cmd('ovs-ofctl -O OpenFlow13 add-flow %s "priority=0,actions=NORMAL"' % switch.name)
    if test_normal or test_attack:
        server1 = net.get('server1')
        client1 = net.get('client1')
        attacker1 = net.get('attacker1')
        info("-> Starting HTTP server on server1 (10.0.0.200:80)...\n")
        server1.cmd('python3 -m http.server 80 > /tmp/http_server.log 2>&1 &')
        time.sleep(1.0)
        info("-> Observing Baseline Warm-Up Period (15s)...\n")
        for s in range(15):
            client1.cmd('curl -s -o /dev/null http://10.0.0.200:80 &')
            time.sleep(1.0)
        info("-> Testing Legitimate Traffic...\n")
        net.pingAll()
        client1.cmd('curl -s -o /dev/null http://10.0.0.200:80')
        time.sleep(3.0)
        if test_attack:
            info("-> GENERATING CONTROLLED LAB ATTACK TRAFFIC (attacker1 -> server1)...\n")
            attacker1.cmd('hping3 --flood -S -p 80 10.0.0.200 > /dev/null 2>&1 &')
            for sec in range(10):
                time.sleep(1.0)
            attacker1.cmd('pkill -f hping3')
            info("-> Lab attack stopped.\n")
        server1.cmd('pkill -f "http.server"')
        net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', choices=['default', 'remote'], default='default')
    parser.add_argument('--ip', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=6653)
    parser.add_argument('--test-normal', action='store_true')
    parser.add_argument('--test-attack', action='store_true')
    args = parser.parse_args()
    run_topology(controller_type=args.controller, controller_ip=args.ip, controller_port=args.port, test_normal=args.test_normal, test_attack=args.test_attack)
'''

base_dir = os.path.expanduser("~/CN_CP")
os.makedirs(os.path.join(base_dir, "detection"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "topology"), exist_ok=True)

with open(os.path.join(base_dir, "detection", "ddos_detector.py"), "w") as f:
    f.write(det_code)

with open(os.path.join(base_dir, "topology", "sdn_topo.py"), "w") as f:
    f.write(topo_code)

print("SUCCESS: Phase 4 files updated with per-datapath persistence!")
