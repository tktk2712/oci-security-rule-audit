#!/usr/bin/env python3
# OCI SL/NSG抽出
# Usage: python3 seclist2csv.py [seclist2csv.conf]

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from datetime import datetime


HEADER = [
    "KIND", "NAME", "STATELESS", "DIRECTION", "SOURCE IP", "DEST IP",
    "PROTOCOL", "TCP SRC MIN", "TCP SRC MAX", "TCP DST MIN", "TCP DST MAX",
    "UDP SRC MIN", "UDP SRC MAX", "UDP DST MIN", "UDP DST MAX",
    "ICMP TYPE", "ICMP CODE", "OCID", "REGION", "VCN NAME", "VCN OCID",
]
CSV_NAME = re.compile(r"seclist_[0-9]{8}_[0-9]{6}_[0-9]+\.csv\Z")

# 既存confの配列・${HOME}展開を維持するため、読み込みだけBashで行う
# 元のsourceと同じく、管理者が管理する信頼できるconfに限る
# 値はNUL区切りで受け取り、空白や改行を含むパスも分割しない
LOAD_CONF = r'''
set -euo pipefail
source "$1"
[[ -n "${COMP_OCID:-}" ]] || {
    echo 'COMP_OCIDが未設定です。' >&2; exit 1;
}
if [[ "$(declare -p REGIONS 2>/dev/null || true)" != "declare -a REGIONS="* ]]; then
    echo 'REGIONSをBash配列で設定してください。' >&2; exit 1
fi
(( ${#REGIONS[@]} > 0 )) || {
    echo 'REGIONSが空です。' >&2; exit 1;
}
printf '%s\0' "$COMP_OCID" "${OUTPUT_DIR:-./output}" \
    "${KEEP_GENERATIONS:-3}" "${OCI_CONFIG_FILE:-$HOME/.oci/config}" \
    "${OCI_PROFILE:-DEFAULT}" "${#REGIONS[@]}" "${REGIONS[@]}"
'''


class ExtractError(Exception):
    pass


def log(message):
    print(message, file=sys.stderr, flush=True)


def conf_path(value, base):
    path = Path(value)
    return path if path.is_absolute() else base / path


def load_config(filename):
    path = Path(filename).resolve()
    if not path.is_file():
        raise ExtractError("configがありません: {}".format(path))
    if shutil.which("bash") is None:
        raise ExtractError("必要なコマンドがありません: bash")
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", LOAD_CONF, "seclist2csv", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.stderr:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
    if result.returncode:
        raise ExtractError("configの読み込みに失敗しました: {}".format(path))
    fields = result.stdout.decode("utf-8").split("\0")
    if (len(fields) < 8 or fields[-1] != "" or not fields[5].isdigit()
            or len(fields) != 7 + int(fields[5])):
        raise ExtractError("configの形式が不正です。conf内で標準出力へ出力しないでください。")
    comp, out, keep, auth, profile = fields[:5]
    regions = fields[6:-1]
    if not regions:
        raise ExtractError("REGIONSが空です。")
    for region in regions:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", region):
            raise ExtractError("リージョンの指定が不正です: {}".format(region))
    if not re.fullmatch(r"[1-9][0-9]{0,8}", keep):
        raise ExtractError("KEEP_GENERATIONSには1～999999999を指定してください。")
    auth_path = conf_path(auth, path.parent)
    if not auth_path.is_file() or not os.access(str(auth_path), os.R_OK):
        raise ExtractError("OCI認証設定を読み込めません: {}".format(auth_path))
    return {
        "compartment": comp, "regions": regions,
        "output": conf_path(out, path.parent).resolve(),
        "keep": int(keep), "auth": str(auth_path), "profile": profile,
    }


class OCI:
    def __init__(self, config):
        os.environ["SUPPRESS_LABEL_WARNING"] = "True"
        try:
            import oci
        except ImportError as exc:
            raise ExtractError("OCI Python SDKを読み込めません。python3 -m pip install oci を実行してください: {}".format(exc))
        self.sdk = oci
        try:
            self.auth = oci.config.from_file(
                file_location=config["auth"], profile_name=config["profile"])
            oci.config.validate_config(self.auth)
        except Exception as exc:
            raise ExtractError("OCI認証設定の読み込みに失敗しました: {}".format(exc))
        self.clients = {}

    def call(self, region, method, **kwargs):
        try:
            if region not in self.clients:
                # リージョンごとに独立したクライアントを作り、既存接続を再利用する
                auth = dict(self.auth, region=region)
                self.clients[region] = self.sdk.core.VirtualNetworkClient(
                    auth, timeout=(10, 120),
                    retry_strategy=self.sdk.retry.DEFAULT_RETRY_STRATEGY)
            function = getattr(self.clients[region], method)
            if method.startswith("list_"):
                response = self.sdk.pagination.list_call_get_all_results(function, **kwargs)
            else:
                response = function(**kwargs)
            data = self.sdk.util.to_dict(response.data)
        except Exception as exc:
            raise ExtractError("OCI SDK失敗: {} / {}: {}".format(region, method, exc))
        expected = list if method.startswith("list_") else dict
        if not isinstance(data, expected):
            raise ExtractError("OCI SDKのdata形式が不正です: {}".format(method))
        # SDKのsnake_caseを元シェルの内部フィールド名に対応させるだけで、値は変更しない。
        return sdk_fields(data)


def sdk_fields(value):
    if isinstance(value, dict):
        return {key.replace("_", "-"): sdk_fields(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sdk_fields(item) for item in value]
    return value


def csv_cell(value):
    """jq @csvと同様: 文字列は引用、boolは小文字、nullは空欄"""
    if value is None:
        return ""
    if isinstance(value, str):
        return '"' + value.replace('"', '""') + '"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value, allow_nan=False)
    raise ExtractError("CSVに出力できない値の型です: {}".format(type(value).__name__))


def text_value(value):
    # jq -rで取得して--argで渡していたフィールドに対応。
    return "null" if value is None else str(value)


def required(record, key):
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ExtractError("OCI応答の必須フィールドが不正です: {}".format(key))
    return value


def ports(value):
    return ["ALL", "ALL"] if value is None else [value.get("min"), value.get("max")]


def protocol_ports(rule, protocol, option):
    if str(rule.get("protocol")) != protocol:
        return [None] * 4
    options = rule.get(option) or {}
    return ports(options.get("source-port-range")) + ports(options.get("destination-port-range"))


def rule_row(rule, kind, name, local_ip, resource_id, direction, region, vcn):
    endpoints = ([local_ip, rule.get("destination")] if direction == "EGRESS"
                 else [rule.get("source"), local_ip])
    icmp = [None, None]
    # 元シェルどおりprotocol=1のみ。58の扱いは変更しない。
    if str(rule.get("protocol")) == "1":
        option = rule.get("icmp-options")
        icmp = (["ALL", "ALL"] if option is None
                else [option.get("type"), option.get("code")])
    return ([kind, name, rule.get("is-stateless"), direction] + endpoints
            + [rule.get("protocol")]
            + protocol_ports(rule, "6", "tcp-options")
            + protocol_ports(rule, "17", "udp-options")
            + icmp + [resource_id, region, text_value(vcn.get("display-name")), vcn["id"]])


def emit_rules(stream, data, kind, name, local_ip, resource_id, region, vcn):
    for direction in ("EGRESS", "INGRESS"):
        if kind == "SL":
            rules = data.get(direction.lower() + "-security-rules")
            if not isinstance(rules, list):
                raise ExtractError("SLのルール配列が不正です: {}".format(resource_id))
        else:
            rules = [rule for rule in data if rule.get("direction") == direction]
        for rule in rules:
            row = rule_row(rule, kind, name, local_ip, resource_id, direction, region, vcn)
            stream.write(",".join(csv_cell(value) for value in row) + "\n")


def extract(config, api, stream):
    stream.write(",".join(HEADER) + "\n")
    for region in config["regions"]:
        log("Region: {}".format(region))
        vcns = api.call(region, "list_vcns", compartment_id=config["compartment"])
        if not vcns:
            log("  VCNなし")
        for vcn in vcns:
            vcn_id = required(vcn, "id")
            log("VCN: {} ({})".format(text_value(vcn.get("display-name")), vcn_id))
            subnets = api.call(region, "list_subnets", compartment_id=config["compartment"],
                               vcn_id=vcn_id)
            for subnet in subnets:
                cidr = text_value(subnet.get("cidr-block"))
                sl_ids = subnet.get("security-list-ids")
                if not isinstance(sl_ids, list):
                    raise ExtractError("サブネットのsecurity-list-idsが不正です。")
                for sl_id in sl_ids:
                    log("  SL: {} / Subnet: {}".format(sl_id, cidr))
                    sl = api.call(region, "get_security_list", security_list_id=sl_id)
                    emit_rules(stream, sl, "SL", text_value(sl.get("display-name")), cidr,
                               sl_id, region, vcn)
            nsgs = api.call(region, "list_network_security_groups", compartment_id=config["compartment"],
                            vcn_id=vcn_id)
            for nsg in nsgs:
                nsg_id = required(nsg, "id")
                name = text_value(nsg.get("display-name"))
                vnics = api.call(region, "list_network_security_group_vnics", network_security_group_id=nsg_id)
                if not vnics:
                    log("  Skip: VNIC未所属のNSG: {} ({})".format(name, nsg_id))
                    continue
                rules = api.call(region, "list_network_security_group_security_rules", network_security_group_id=nsg_id)
                for attachment in vnics:
                    vnic = api.call(region, "get_vnic", vnic_id=required(attachment, "vnic-id"))
                    private_ip = text_value(vnic.get("private-ip"))
                    log("  NSG: {} / VNIC: {}".format(name, private_ip))
                    emit_rules(stream, rules, "NSG", name, private_ip, nsg_id, region, vcn)


def run(config, api):
    output_dir = config["output"]
    output_dir.mkdir(parents=True, exist_ok=True)
    # 既存シェルと同じロック。ファイルは削除せずプロセス終了で解放する
    with (output_dir / ".seclist2csv.lock").open("a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ExtractError("同じ出力先に対する抽出が実行中です")
        with tempfile.TemporaryDirectory(prefix=".seclist2csv.", dir=str(output_dir)) as work:
            temp_path = Path(work) / "result.csv"
            with temp_path.open("w", encoding="utf-8", newline="") as stream:
                extract(config, api, stream)
                stream.flush()
                os.fsync(stream.fileno())
            filename = "seclist_{}_{}.csv".format(datetime.now().strftime("%Y%m%d_%H%M%S"), os.getpid())
            output_file = output_dir / filename
            # 完成済みCSVを一度に公開。衝突時はFileExistsErrorで上書きしない
            os.link(str(temp_path), str(output_file))
            log("CSV作成完了: {}".format(output_file))
            # 元シェルと同じく更新時刻ではなくファイル名の降順
            files = sorted((p for p in output_dir.iterdir()
                            if CSV_NAME.fullmatch(p.name) and p.is_file()),
                           key=lambda p: p.name, reverse=True)
            for old in files[config["keep"]:]:
                old.unlink()
                log("Deleted: {}".format(old))
            return output_file


def terminate(signum, frame):
    raise ExtractError("シグナル{}を受信したため中止しました".format(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("conf", nargs="?", default=str(Path(__file__).resolve().with_name("seclist2csv.conf")))
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, terminate)
    try:
        config = load_config(args.conf)
        output_file = run(config, OCI(config))
    except KeyboardInterrupt:
        log("Error: 処理を中止しました。")
        return 130
    except (ExtractError, OSError, ValueError, TypeError, AttributeError) as exc:
        log("Error: {}".format(exc))
        return 1
    print(output_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
