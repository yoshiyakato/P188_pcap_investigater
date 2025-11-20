import sys
import csv
from collections import defaultdict
from scapy.all import PcapReader, IP, IPv6
import pandas as pd
import ipaddress  # IPアドレス処理ライブラリをインポート

# --- ▼ 統合したいネットワークをここに追加・編集してください ▼ ---
GROUP_NETWORKS_STR = [
    # 前回指定されたもの
    "192.168.128.0/19",
    "192.168.32.0/19",
    # 今回追加指定されたもの
    "192.168.100.0/23",
    "224.0.0.0/24",  # マルチキャスト
    "239.0.0.0/8"    # マルチキャスト
]
# --- ▲ --------------------------------------------------- ▲ ---

# 高速化のため、文字列のリストを事前にipaddressオブジェクトのリストに変換
try:
    GROUP_NETWORKS = [ipaddress.ip_network(net) for net in GROUP_NETWORKS_STR]
    print(f"[*] 以下のネットワークをグループとして集計します: {GROUP_NETWORKS_STR}")
except ValueError as e:
    print(f"[エラー] ネットワーク定義に誤りがあります: {e}", file=sys.stderr)
    print("GROUP_NETWORKS_STR のCIDR表記を確認してください。")
    sys.exit(1)


def get_group_key(ip_str):
    """
    【新機能】
    IPアドレス文字列を受け取り、定義済みグループに属していれば
    グループのCIDR文字列を、属していなければ元のIP文字列を返す。
    """
    try:
        # %eth0 などのゾーンID（IPv6）を削除
        ip_addr = ipaddress.ip_address(ip_str.split('%')[0])
    except ValueError:
        return ip_str # IPアドレスとしてパースできなければそのまま返す

    # 定義済みネットワークを順にチェック
    for network in GROUP_NETWORKS:
        if ip_addr in network:
            # 属しているネットワークのCIDR文字列をキーとして返す
            return str(network)
    
    # どのグループにも属していなければ元のIP文字列をキーとして返す
    return ip_str


def analyze_multiple_pcaps(pcap_files, output_excel_file):
    """
    【改良版 v5.1】
    複数のPcapファイルを解析し、通信量を統合して集計する。
    指定されたネットワーク範囲はグルーピングする。
    """
    
    def create_stats():
        return {'packets': 0, 'total_bytes': 0, 'ip_packet_bytes': 0, 'transport_payload_bytes': 0}

    sd_traffic = defaultdict(create_stats)
    s_traffic = defaultdict(create_stats)
    d_traffic = defaultdict(create_stats)
    total_traffic = defaultdict(create_stats)

    print(f"[*] {len(pcap_files)} 個のファイルの統合解析を開始します...")
    global_packet_count = 0 

    for pcap_file in pcap_files:
        print(f"[*] ... {pcap_file} を処理中 ...")
        
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for pkt in pcap_reader:
                    global_packet_count += 1
                    
                    if global_packet_count % 100000 == 0:
                        print(f"[*] ... 合計 {global_packet_count:,} パケット処理済み ...")

                    src_ip_orig, dst_ip_orig = None, None
                    pkt_total_len, pkt_ip_len, pkt_transport_payload_len = 0, 0, 0
                    
                    if IP in pkt:
                        src_ip_orig, dst_ip_orig = pkt[IP].src, pkt[IP].dst
                        pkt_total_len = len(pkt)
                        pkt_ip_len = pkt[IP].len 
                        ip_header_len = pkt[IP].ihl * 4
                        pkt_transport_payload_len = pkt_ip_len - ip_header_len
                        
                    elif IPv6 in pkt:
                        src_ip_orig, dst_ip_orig = pkt[IPv6].src, pkt[IPv6].dst
                        pkt_total_len = len(pkt)
                        pkt_transport_payload_len = pkt[IPv6].plen
                        pkt_ip_len = pkt_transport_payload_len + 40 
                        
                    else:
                        continue # IPパケットでなければスキップ

                    # --- IPをグループキー（CIDR or 元のIP）に変換 ---
                    src_key = get_group_key(src_ip_orig)
                    dst_key = get_group_key(dst_ip_orig)

                    # 1. Source-Destination
                    stats_sd = sd_traffic[(src_key, dst_key)] 
                    stats_sd['packets'] += 1
                    stats_sd['total_bytes'] += pkt_total_len
                    stats_sd['ip_packet_bytes'] += pkt_ip_len
                    stats_sd['transport_payload_bytes'] += pkt_transport_payload_len

                    # 2. Source
                    stats_s = s_traffic[src_key] 
                    stats_s['packets'] += 1
                    stats_s['total_bytes'] += pkt_total_len
                    stats_s['ip_packet_bytes'] += pkt_ip_len
                    stats_s['transport_payload_bytes'] += pkt_transport_payload_len

                    # 3. Destination
                    stats_d = d_traffic[dst_key] 
                    stats_d['packets'] += 1
                    stats_d['total_bytes'] += pkt_total_len
                    stats_d['ip_packet_bytes'] += pkt_ip_len
                    stats_d['transport_payload_bytes'] += pkt_transport_payload_len

                    # 4. Total Traffic
                    stats_total_s = total_traffic[src_key] 
                    stats_total_s['packets'] += 1
                    stats_total_s['total_bytes'] += pkt_total_len
                    stats_total_s['ip_packet_bytes'] += pkt_ip_len
                    stats_total_s['transport_payload_bytes'] += pkt_transport_payload_len
                    
                    stats_total_d = total_traffic[dst_key] 
                    stats_total_d['packets'] += 1
                    stats_total_d['total_bytes'] += pkt_total_len
                    stats_total_d['ip_packet_bytes'] += pkt_ip_len
                    stats_total_d['transport_payload_bytes'] += pkt_transport_payload_len

        except FileNotFoundError:
            print(f"[エラー] ファイルが見つかりません: {pcap_file}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[エラー] {pcap_file} の読み込み中に予期せぬエラーが発生しました: {e}", file=sys.stderr)
            continue
    
    # --- 全ファイルのループが終了 ---
    print(f"[*] 全ファイルの解析完了。合計 {global_packet_count:,} パケットを処理しました。")
    print(f"[*] データをソートし、Excelファイル ({output_excel_file}) に出力します...")

    # --- Excel出力処理 (変更なし) ---
    try:
        # 1. Source-Destination Ranking
        header_sd = ['source', 'dest', 'packets', 'total_bytes', 'ip_packet_bytes', 'transport_payload_bytes']
        sd_list = [(key[0], key[1], 
                    val['packets'], val['total_bytes'], val['ip_packet_bytes'], val['transport_payload_bytes']) 
                   for key, val in sd_traffic.items()]
        sd_list.sort(key=lambda x: x[3], reverse=True)
        df_sd = pd.DataFrame(sd_list, columns=header_sd)

        # 2. Source Ranking
        header_s = ['source', 'packets', 'total_bytes', 'ip_packet_bytes', 'transport_payload_bytes']
        s_list = [(key, 
                   val['packets'], val['total_bytes'], val['ip_packet_bytes'], val['transport_payload_bytes']) 
                  for key, val in s_traffic.items()]
        s_list.sort(key=lambda x: x[2], reverse=True)
        df_s = pd.DataFrame(s_list, columns=header_s)

        # 3. Destination Ranking
        header_d = ['dest', 'packets', 'total_bytes', 'ip_packet_bytes', 'transport_payload_bytes']
        d_list = [(key, 
                   val['packets'], val['total_bytes'], val['ip_packet_bytes'], val['transport_payload_bytes']) 
                  for key, val in d_traffic.items()]
        d_list.sort(key=lambda x: x[2], reverse=True)
        df_d = pd.DataFrame(d_list, columns=header_d)

        # 4. Total Traffic Ranking
        header_total = ['ip_address', 'packets', 'total_bytes', 'ip_packet_bytes', 'transport_payload_bytes']
        total_list = [(key, 
                       val['packets'], val['total_bytes'], val['ip_packet_bytes'], val['transport_payload_bytes']) 
                      for key, val in total_traffic.items()]
        total_list.sort(key=lambda x: x[2], reverse=True)
        df_total = pd.DataFrame(total_list, columns=header_total)

        # ExcelWriterを使用して単一のファイルに複数のシートとして書き出す
        with pd.ExcelWriter(output_excel_file, engine='openpyxl') as writer:
            df_sd.to_excel(writer, sheet_name='Source-Dest', index=False)
            df_s.to_excel(writer, sheet_name='Source', index=False)
            df_d.to_excel(writer, sheet_name='Destination', index=False)
            df_total.to_excel(writer, sheet_name='Total_Traffic', index=False)
        
        print(f"[OK] {output_excel_file} にすべての集計結果を出力しました。")

    except Exception as e:
        print(f"[エラー] Excelファイルの書き込み中にエラーが発生しました: {e}", file=sys.stderr)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("使用方法: python analyze_pcaps_excel.py <output_excel_file.xlsx> <pcap_file1> [pcap_file2] ...")
        print("例: python analyze_pcaps_excel.py analysis_result.xlsx capture1.pcap capture2.pcap")
        sys.exit(1)
        
    output_excel_filename = sys.argv[1] 
    pcap_file_paths = sys.argv[2:]      
    
    if not output_excel_filename.lower().endswith('.xlsx'):
        print(f"[警告] 出力ファイル名が .xlsx で終わっていません: {output_excel_filename}")
        print("[*] ... 処理を続行します ...")
        
    analyze_multiple_pcaps(pcap_file_paths, output_excel_filename)