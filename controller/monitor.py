import os, csv, time, datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

SERVER1_MAC = '00:00:00:00:00:fe'

class SimpleMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    DEFAULT_MONITOR_INTERVAL = 1

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_interval = kwargs.get('monitor_interval', self.DEFAULT_MONITOR_INTERVAL)
        self.prev_port_stats = {}
        self.prev_flow_stats = {}
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(repo_root, 'logs', 'traffic')
        os.makedirs(self.log_dir, exist_ok=True)
        self.port_csv_path = os.path.join(self.log_dir, 'port_stats.csv')
        self.flow_csv_path = os.path.join(self.log_dir, 'flow_stats.csv')
        self._init_csv_files()
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info('*** Ryu OpenFlow 1.3 Traffic Monitor Initialized')

    def _init_csv_files(self):
        if not os.path.exists(self.port_csv_path):
            with open(self.port_csv_path, 'w', newline='') as f:
                csv.writer(f).writerow(['timestamp','iso_time','dpid','port_no','rx_packets','tx_packets','rx_bytes','tx_bytes','rx_pps','tx_pps','rx_bps','tx_bps'])
        if not os.path.exists(self.flow_csv_path):
            with open(self.flow_csv_path, 'w', newline='') as f:
                csv.writer(f).writerow(['timestamp','iso_time','dpid','priority','in_port','eth_src','eth_dst','flow_type','packet_count','byte_count','duration_sec','flow_pps','flow_bps','target_server1'])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info(f'*** Monitor Registered Datapath: DPID={dp.id:016x}')
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.info(f'*** Monitor Unregistered Datapath: DPID={dp.id:016x}')
                del self.datapaths[dp.id]

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(self.monitor_interval)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        iso = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        self.prev_port_stats.setdefault(dpid, {})
        with open(self.port_csv_path, 'a', newline='') as f:
            w = csv.writer(f)
            for s in ev.msg.body:
                port, rx_p, tx_p, rx_b, tx_b = s.port_no, s.rx_packets, s.tx_packets, s.rx_bytes, s.tx_bytes
                rx_pps, tx_pps, rx_bps, tx_bps = 0.0, 0.0, 0.0, 0.0
                if port in self.prev_port_stats[dpid]:
                    pt, prx_p, ptx_p, prx_b, ptx_b = self.prev_port_stats[dpid][port]
                    dt = now - pt
                    if dt > 0:
                        rx_pps = max(0.0, (rx_p - prx_p)/dt)
                        tx_pps = max(0.0, (tx_p - ptx_p)/dt)
                        rx_bps = max(0.0, (rx_b - prx_b)*8.0/dt)
                        tx_bps = max(0.0, (tx_b - ptx_b)*8.0/dt)
                self.prev_port_stats[dpid][port] = (now, rx_p, tx_p, rx_b, tx_b)
                w.writerow([f'{now:.3f}', iso, f'{dpid:016x}', port, rx_p, tx_p, rx_b, tx_b, f'{rx_pps:.2f}', f'{tx_pps:.2f}', f'{rx_bps:.2f}', f'{tx_bps:.2f}'])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        iso = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        self.prev_flow_stats.setdefault(dpid, {})
        with open(self.flow_csv_path, 'a', newline='') as f:
            w = csv.writer(f)
            for s in ev.msg.body:
                prio, pkts, bytes_cnt, dur = s.priority, s.packet_count, s.byte_count, s.duration_sec
                in_p = s.match.get('in_port', 'ANY')
                src = s.match.get('eth_src', 'ANY')
                dst = s.match.get('eth_dst', 'ANY')
                flow_type = 'table_miss' if (prio==0 or (src=='ANY' and dst=='ANY')) else ('forwarding' if (prio==1 and src!='ANY' and dst!='ANY') else 'control')
                target_server1 = (str(dst).lower() == SERVER1_MAC.lower())
                key = (prio, str(in_p), str(src), str(dst))
                pps, bps = 0.0, 0.0
                if key in self.prev_flow_stats[dpid]:
                    pt, ppkts, pbytes = self.prev_flow_stats[dpid][key]
                    dt = now - pt
                    if dt > 0:
                        pps = max(0.0, (pkts - ppkts)/dt)
                        bps = max(0.0, (bytes_cnt - pbytes)*8.0/dt)
                self.prev_flow_stats[dpid][key] = (now, pkts, bytes_cnt)
                w.writerow([f'{now:.3f}', iso, f'{dpid:016x}', prio, in_p, src, dst, flow_type, pkts, bytes_cnt, dur, f'{pps:.2f}', f'{bps:.2f}', target_server1])
