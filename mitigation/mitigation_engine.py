import os, csv, time, datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

SERVER1_IP = "10.0.0.200"
SERVER1_MAC = "00:00:00:00:00:fe"

class DDoSBlocker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    DEFAULT_SUSPICION_THRESHOLD = 60
    DROP_PRIORITY = 100

    def __init__(self, *args, **kwargs):
        super(DDoSBlocker, self).__init__(*args, **kwargs)
        self.suspicion_threshold = kwargs.get('suspicion_threshold', self.DEFAULT_SUSPICION_THRESHOLD)
        self.blocked_attackers = set()
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(repo_root, "logs", "detection")
        os.makedirs(self.log_dir, exist_ok=True)
        self.mitigation_csv = os.path.join(self.log_dir, "mitigation_events.csv")
        self.log_path = os.path.join(self.log_dir, "detection.log")
        self._init_csv_file()
        self.logger.info("==================================================")
        self.logger.info("   Ryu OpenFlow 1.3 Automatic DDoS Mitigation Engine Initialized")
        self.logger.info("==================================================")

    def _init_csv_file(self):
        if not os.path.exists(self.mitigation_csv):
            with open(self.mitigation_csv, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'iso_time', 'dpid', 'attacker_mac', 'target_ip', 'target_mac', 'action', 'priority', 'status'])

    def _log_event(self, msg):
        self.logger.info(msg)
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_path, 'a') as f:
            f.write(f"[{now_str}] [MITIGATION] {msg}\n")

    def block_attacker(self, datapath, attacker_mac):
        if attacker_mac.lower() in self.blocked_attackers:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=attacker_mac.lower(), eth_dst=SERVER1_MAC.lower())
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=self.DROP_PRIORITY, match=match,
            idle_timeout=0, hard_timeout=0, instructions=inst
        )
        datapath.send_msg(mod)
        self.blocked_attackers.add(attacker_mac.lower())
        now = time.time()
        iso_str = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        self._log_event(
            f"⛔ AUTOMATIC MITIGATION APPLIED: Installed OpenFlow DROP Rule (priority={self.DROP_PRIORITY}) "
            f"on DPID={datapath.id:016x} for Attacker MAC={attacker_mac} -> server1 ({SERVER1_MAC})"
        )
        with open(self.mitigation_csv, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([f"{now:.3f}", iso_str, f"{datapath.id:016x}", attacker_mac, SERVER1_IP, SERVER1_MAC, "DROP_FLOW_INSTALLED", self.DROP_PRIORITY, "ACTIVE"])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        source_pkt_rates = {}
        for stat in body:
            priority = stat.priority
            pkts = stat.packet_count
            eth_dst = str(stat.match.get('eth_dst', '')).lower()
            eth_src = str(stat.match.get('eth_src', '')).lower()
            if priority == 1 and eth_dst == SERVER1_MAC.lower() and eth_src != 'any':
                dur = max(1.0, float(stat.duration_sec))
                rate = pkts / dur
                source_pkt_rates[eth_src] = rate

        for src_mac, rate in source_pkt_rates.items():
            if src_mac.lower() == SERVER1_MAC.lower():
                continue
            if rate > 25.0:
                self.logger.warning(f"⚠️ HIGH TRAFFIC DETECTED from Source MAC={src_mac}: {rate:.1f} pps")
                self.block_attacker(datapath, src_mac)
