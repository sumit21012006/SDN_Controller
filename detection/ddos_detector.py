#!/usr/bin/env python3
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
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(repo_root, "logs", "detection")
        os.makedirs(self.log_dir, exist_ok=True)
        self.home_log_dir = os.path.join(os.path.expanduser("~"), "CN_CP", "logs", "detection")
        os.makedirs(self.home_log_dir, exist_ok=True)
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
