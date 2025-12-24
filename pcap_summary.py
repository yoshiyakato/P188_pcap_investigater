#!/usr/bin/env python3
"""
pcap_summary.py - PCAPファイルの概要情報を表示するツール

出力内容:
  - キャプチャ開始時刻
  - キャプチャ終了時刻
  - キャプチャ時間（duration）
  - 総パケット数
  - 総データ量（バイト）
"""

import sys
from datetime import datetime
from scapy.all import PcapReader


def format_bytes(size_bytes):
    """バイト数を人間が読みやすい形式に変換"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def format_duration(seconds):
    """秒数を時間:分:秒の形式に変換"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = seconds % 60
    if hours > 0:
        return f"{hours}時間 {minutes}分 {secs:.2f}秒"
    elif minutes > 0:
        return f"{minutes}分 {secs:.2f}秒"
    else:
        return f"{secs:.2f}秒"


def analyze_pcap(pcap_file):
    """PCAPファイルを解析し、概要情報を返す"""
    first_timestamp = None
    last_timestamp = None
    packet_count = 0
    total_bytes = 0

    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                total_bytes += len(pkt)

                # パケットのタイムスタンプを取得
                pkt_time = float(pkt.time)

                if first_timestamp is None:
                    first_timestamp = pkt_time
                last_timestamp = pkt_time

                # 進捗表示（10万パケットごと）
                if packet_count % 100000 == 0:
                    print(f"  ... {packet_count:,} パケット処理済み ...", file=sys.stderr)

    except FileNotFoundError:
        print(f"[エラー] ファイルが見つかりません: {pcap_file}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[エラー] ファイル読み込み中にエラーが発生: {e}", file=sys.stderr)
        return None

    if packet_count == 0:
        print(f"[警告] パケットが見つかりませんでした: {pcap_file}", file=sys.stderr)
        return None

    return {
        'file': pcap_file,
        'first_timestamp': first_timestamp,
        'last_timestamp': last_timestamp,
        'packet_count': packet_count,
        'total_bytes': total_bytes
    }


def print_summary(result):
    """解析結果を整形して出力"""
    if result is None:
        return

    start_time = datetime.fromtimestamp(result['first_timestamp'])
    end_time = datetime.fromtimestamp(result['last_timestamp'])
    duration = result['last_timestamp'] - result['first_timestamp']

    print("=" * 60)
    print(f"ファイル: {result['file']}")
    print("=" * 60)
    print(f"キャプチャ開始時刻: {start_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    print(f"キャプチャ終了時刻: {end_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    print(f"キャプチャ時間:     {format_duration(duration)}")
    print("-" * 60)
    print(f"総パケット数:       {result['packet_count']:,}")
    print(f"総データ量:         {format_bytes(result['total_bytes'])} ({result['total_bytes']:,} bytes)")
    print("=" * 60)


def main():
    if len(sys.argv) < 2:
        print("使用方法: python pcap_summary.py <pcap_file> [pcap_file2] ...")
        print("例: python pcap_summary.py capture.pcap")
        print("    python pcap_summary.py *.pcap")
        sys.exit(1)

    pcap_files = sys.argv[1:]

    for pcap_file in pcap_files:
        print(f"\n[*] {pcap_file} を解析中...", file=sys.stderr)
        result = analyze_pcap(pcap_file)
        print_summary(result)
        print()


if __name__ == '__main__':
    main()
