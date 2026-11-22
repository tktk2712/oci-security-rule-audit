#!/usr/bin/env python3
# 既存の抽出CSVを変更せず比較し、差分があればOCI Email Deliveryで送信
# Usage: python3 seclist_diff.py
import argparse
import configparser
import csv
import fcntl
import hashlib
import io
import json
import os
import re
import smtplib
import ssl
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate, make_msgid
from pathlib import Path

from seclist_genai import analyze_diff, render_analysis


FILE_PATTERN = re.compile(r"^seclist_(\d{8})_(\d{6})_(\d+)\.csv$")
REQUIRED_COLUMNS = {
    "KIND", "NAME", "STATELESS", "DIRECTION", "SOURCE IP", "DEST IP",
    "PROTOCOL", "OCID", "REGION", "VCN NAME", "VCN OCID",
}


def config_path(value, base):
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def load_config(path):
    conf = configparser.ConfigParser(interpolation=None)
    with path.open(encoding="utf-8-sig") as stream:
        conf.read_file(stream)
    if not conf.has_section("files"):
        raise ValueError("configに[files]がありません。")
    return conf


@contextmanager
def file_lock(path, shared=False, create=True):
    flags = os.O_RDONLY if shared else os.O_RDWR
    if create:
        flags |= os.O_CREAT
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileNotFoundError:
        if not create:
            yield False
            return
        raise
    with os.fdopen(fd, "rb" if shared else "r+b") as stream:
        try:
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
                        | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("他の処理が実行中です。後で再実行してください: " + str(path))
        try:
            yield True
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def latest_two(directory):
    candidates = []
    for path in directory.iterdir():
        match = FILE_PATTERN.fullmatch(path.name)
        if match and path.is_file() and not path.is_symlink():
            stamp = datetime.strptime(match[1] + match[2], "%Y%m%d%H%M%S")
            candidates.append(((stamp, int(match[3])), path))
    candidates.sort(key=lambda item: item[0], reverse=True)
    if len(candidates) < 2:
        raise ValueError("比較には seclist_YYYYMMDD_HHMMSS_PID.csv が2ファイル以上必要です")
    # 同一秒に複数回実行された場合、PIDは実行順を保証しない。
    if candidates[0][0][0] == candidates[1][0][0]:
        raise ValueError("最新候補の日時が同一秒です。実行順を判別できないため比較を中止しました")
    return candidates[0][1], candidates[1][1]


def read_snapshot(path):
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    identity = lambda s: (s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if identity(before) != identity(after) or len(data) != after.st_size:
        raise RuntimeError("読取り中にCSVが変更されました: " + str(path))
    reader = csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError("CSVが空です: " + str(path))
    if len(header) != len(set(header)) or not REQUIRED_COLUMNS.issubset(header):
        raise ValueError("CSVヘッダーに重複または必須列の欠落があります: " + str(path))
    if "CHANGE_TYPE" in header:
        raise ValueError("差分CSVを入力には使用できません: " + str(path))
    rows = []
    for row in reader:
        if not row:  # 物理的な空行のみ無視。各セルの空白や空欄は変更しない
            continue
        if len(row) != len(header):
            raise ValueError("CSVの列数が不一致です: {} 行{}".format(path, reader.line_num))
        rows.append(tuple(row))
    return header, rows, hashlib.sha256(data).hexdigest()


def compare(current_header, current_rows, previous_header, previous_rows):
    if set(current_header) != set(previous_header):
        raise ValueError("前回と今回の列構成が異なります。誤検出を防ぐため中止しました")
    indices = [previous_header.index(name) for name in current_header]
    previous = Counter(tuple(row[i] for i in indices) for row in previous_rows)
    current = Counter(current_rows)
    return current - previous, previous - current


def diff_bytes(header, added, removed):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(["CHANGE_TYPE"] + header)
    for kind, counter in (("ADDED", added), ("REMOVED", removed)):
        for row, count in sorted(counter.items()):
            for _ in range(count):
                writer.writerow([kind] + list(row))
    # Excelで日本語名を開けるようBOMを付ける。セル値は変更しない
    return stream.getvalue().encode("utf-8-sig")


def atomic_write(path, payload):
    fd, temporary = tempfile.mkstemp(prefix=".tmp_", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_message(conf, subject, body, attachment, payload):
    sender = conf.get("mail", "from_address").strip()
    recipients = [value.strip() for value in conf.get("mail", "to_addresses").split(",")
                  if value.strip()]
    if not sender or not recipients:
        raise ValueError("from_addressとto_addressesを設定してください。")
    # 設定は表示名なしのメールアドレスのみ。
    for address in [sender] + recipients:
        if not re.fullmatch(r'[^\s@<>,;]+@[^\s@<>,;]+', address):
            raise ValueError("メールアドレスの形式が不正です。表示名なしで指定してください")
    msg = EmailMessage(policy=SMTP)
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body, charset="utf-8")
    msg.add_attachment(payload, maintype="text", subtype="csv",
                       filename=attachment, params={"charset": "utf-8"})
    return msg, sender, recipients


def send_mail(conf, base, subject, body, attachment, payload):
    msg, sender, recipients = build_message(conf, subject, body, attachment, payload)
    max_bytes = conf.getint("mail", "max_message_bytes", fallback=2000000)
    if max_bytes <= 0 or len(msg.as_bytes()) > max_bytes:
        raise ValueError("添付を含むメールがmax_message_bytesを超えています。差分CSVは保存済みです")
    username_env = conf.get("mail", "username_env", fallback="OCI_SMTP_USERNAME")
    password_env = conf.get("mail", "password_env", fallback="OCI_SMTP_PASSWORD")
    username = os.environ.get(username_env) or conf.get("mail", "username", fallback="").strip()
    password = os.environ.get(password_env)
    if not password:
        password_file = conf.get("mail", "password_file", fallback="").strip()
        if password_file:
            secret = config_path(password_file, base)
            if secret.stat().st_mode & 0o077:
                raise ValueError("SMTPパスワードファイルの権限を600にしてください")
            password = secret.read_text(encoding="utf-8").rstrip("\r\n")
    if not username or not password:
        raise ValueError("Email DeliveryのSMTPユーザー名・SMTPパスワードが未設定です")
    host = conf.get("mail", "smtp_host").strip()
    port = conf.getint("mail", "smtp_port", fallback=587)
    mode = conf.get("mail", "tls_mode", fallback="starttls").lower()
    timeout = conf.getint("mail", "timeout_seconds", fallback=60)
    context = ssl.create_default_context()
    if mode == "starttls":
        connection = smtplib.SMTP(host, port, timeout=timeout)
    elif mode == "ssl":
        connection = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        raise ValueError("tls_modeはstarttlsまたはsslを指定してください")
    with connection as smtp:
        smtp.ehlo()
        if mode == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        smtp.login(username, password)
        refused = smtp.send_message(msg, from_addr=sender, to_addrs=recipients)
        if refused:
            raise RuntimeError("一部宛先がSMTPで拒否されました。全宛先への送信成功ではありません")


def run(conf_path, no_mail=False, no_ai=False):
    conf_path = conf_path.resolve()
    conf = load_config(conf_path)
    base = conf_path.parent
    source = config_path(conf.get("files", "csv_dir"), base).resolve()
    destination = config_path(conf.get("files", "diff_dir"), base).resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    with file_lock(destination / ".seclist_diff.lock"):
        # 元の抽出シェルが同名ロックをflockしている場合、抽出中の読取りを防ぐ
        # 抽出シェルは一切変更しない
        with file_lock(source / ".seclist2csv.lock", shared=True, create=False) as locked:
            current, previous = latest_two(source)
            ch, cr, current_hash = read_snapshot(current)
            ph, pr, previous_hash = read_snapshot(previous)
        added, removed = compare(ch, cr, ph, pr)
        added_count, removed_count = sum(added.values()), sum(removed.values())
        changed = bool(added_count or removed_count)
        prefix = "diff_{}_to_{}".format(previous.stem[8:], current.stem[8:])
        output = destination / (prefix + ".csv")
        payload = diff_bytes(ch, added, removed)
        atomic_write(output, payload)
        now = datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")
        body = "\n".join([
            "OCI SL/NSG CSV差分検出", "実行日時: " + now,
            "前回: " + previous.name, "今回: " + current.name,
            "前回行数: " + str(len(pr)), "今回行数: " + str(len(cr)),
            "差分: " + ("あり" if changed else "なし"),
            "追加: {}件 / 削除: {}件".format(added_count, removed_count),
            "", "CHANGE_TYPE: ADDED=今回追加、REMOVED=前回から削除",
            "値の変更は旧行のREMOVEDと新行のADDEDとして記録します。",
            "行順とCSVの引用符・改行形式の違いは差分に含めません。",
            "各セルの値・空欄は補完せず、重複行の件数も比較しています。",
            "検出範囲は抽出CSV内のみです。抽出の完全性は保証しません。",
        ]) + "\n"
        summary = {
            "created_at": now, "current_file": str(current), "previous_file": str(previous),
            "current_sha256": current_hash, "previous_sha256": previous_hash,
            "current_rows": len(cr), "previous_rows": len(pr),
            "added_rows": added_count, "removed_rows": removed_count, "changed": changed,
            "extractor_lock_used": locked, "diff_csv": str(output),
            "mail_status": "pending" if changed else "not_needed",
        }
        summary_path = destination / (prefix + ".json")

        def save_summary():
            atomic_write(summary_path, (json.dumps(summary, ensure_ascii=False, indent=2)
                                       + "\n").encode("utf-8"))

        save_summary()
        if changed and not no_ai and conf.getboolean("genai", "enabled", fallback=False):
            analysis = analyze_diff(conf, base, payload)
            summary["ai_analysis"] = analysis
            body += render_analysis(analysis)
        else:
            reason = "差分なし" if not changed else "AI評価無効"
            summary["ai_analysis"] = {"status": "skipped", "reason": reason}
            body += "\nAI評価: " + reason + "\n"
            body += "推定AI料金 [分析]: JPY 0.00000（API呼出しなし）\n"
        atomic_write(destination / (prefix + ".txt"), body.encode("utf-8"))
        save_summary()
        print(body, end="")
        print("差分CSV: " + str(output), flush=True)
        if not locked:
            print("注意: 抽出ロックがありません。抽出完了後に実行してください", file=sys.stderr)
        if changed:
            if no_mail or not conf.getboolean("mail", "enabled", fallback=False):
                summary["mail_status"] = "disabled"
                print("メール: 無効（送信していません）")
            else:
                try:
                    subject = conf.get("mail", "subject_prefix", fallback="[OCI SL/NSG差分]")
                    subject += " 追加{}件・削除{}件".format(added_count, removed_count)
                    send_mail(conf, base, subject, body, output.name, payload)
                except Exception:
                    summary["mail_status"] = "failed_or_partial"
                    save_summary()
                    raise
                summary["mail_status"] = "accepted_by_smtp"
                print("メール: SMTPサーバー受付完了（最終配送は配信ログで確認）")
        else:
            print("メール: 差分なしのため送信しません")
        save_summary()
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        default=Path(__file__).resolve().with_name("seclist_diff.conf"))
    parser.add_argument("--no-mail", action="store_true", help="差分を保存するがメールは送らない")
    parser.add_argument("--no-ai", action="store_true", help="生成AIの呼出しを省略する")
    args = parser.parse_args()
    # 生成する差分CSV・ログにはネットワーク構成情報が含まれる
    os.umask(0o077)
    try:
        return run(args.config, args.no_mail, args.no_ai)
    except Exception as error:
        # SMTP例外の内容には認証情報・サーバー応答が含まれ得るため、そのまま出さない。
        if isinstance(error, smtplib.SMTPException):
            print("Error: SMTP送信失敗 ({}). Email Deliveryの設定・配信ログを確認してください。"
                  .format(type(error).__name__), file=sys.stderr)
        else:
            print("Error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
