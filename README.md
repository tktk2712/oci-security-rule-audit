# oci-security-rule-audit

OCIのSecurity List（SL）とNetwork Security Group（NSG）をCSVに抽出し、前回との差分をOCI Generative AIで評価してメール通知するツールです。

## 解説記事

構成、OCI側の事前準備、設定方法、定期実行、制約事項は、以下のQiita記事をご覧ください。

*掲載予定*
[OCIのSecurity List/NSGを監査 - 差分検出と生成AIによるリスク評価](https://qiita.com/tktk2712)

## 主な機能

- 指定コンパートメント・複数リージョンのVCNを検出し、SL・NSGのルールをCSVに抽出
- 抽出CSVの世代管理（保存世代数は設定可能）
- 最新と一つ前のCSVを比較し、追加・削除を差分CSVに保存
- 差分CSVだけをOCI Generative AIで評価し、評価サマリと推定料金を作成
- OCI Email Deliveryで評価サマリを本文に記載し、差分CSVを添付して送信

## 動作確認環境

- Linux
- Python 3.12
- Bash（抽出用設定ファイルの読み込みに使用）

Pythonは3.12で動作確認しています。3.12を必須とするものではありません。他のバージョンでの動作は未確認です。利用するOCI SDKが対応するPythonバージョンを使用してください。

以下の実行例では `python3` を使用します。SDKのインストールとプログラムの実行には、同じPython環境を使用してください。

## ファイル構成

| ファイル | 役割 |
| --- | --- |
| `seclist2csv.py` | 指定リージョンのVCNを検出し、SL・NSGをCSVに抽出 |
| `seclist2csv.conf.example` | 抽出用の設定例（Bash形式） |
| `seclist_diff.py` | 最新と一つ前のCSVを比較し、差分CSVを保存・メール送信 |
| `seclist_diff.conf.example` | 差分検出・AI評価・メール送信用の設定例（INI形式） |
| `seclist_genai.py` | 差分のAI評価と推定料金の算出 |
| `requirements.txt` | Python依存パッケージ |

## 使用方法

OCI認証・IAM権限、生成AI、Email Deliveryの準備はQiita記事を参照してください。以下はリポジトリのディレクトリ内で実行します。

### 1. パッケージのインストール

```bash
python3 -m pip install -r requirements.txt
```

### 2. 設定ファイルの準備

```bash
cp seclist2csv.conf.example seclist2csv.conf
cp seclist_diff.conf.example seclist_diff.conf
```

`<<` と `>>` を含む各プレースホルダー全体を、適切な値に置き換えてください。

SMTPパスワードをファイルから読み込む場合は、設定したパスワードファイルに実際のパスワードだけを1行で保存します。説明コメントや引用符は含めません。

```bash
chmod 600 seclist2csv.conf seclist_diff.conf smtp_password.txt
```

環境変数 `OCI_SMTP_PASSWORD` を使用する場合、パスワードファイルは不要です。その場合は上記の `chmod` 対象から `smtp_password.txt` を外してください。

### 3. CSV抽出

```bash
python3 seclist2csv.py
```

最新と一つ前を比較するため、正常に抽出したCSVが2ファイル以上必要です。継続して比較する場合、保存世代数は2以上に設定してください。

### 4. 差分検出・AI評価・メール通知

メールを送らずに確認する場合：

```bash
python3 seclist_diff.py --no-mail
```

`--no-mail` はメール送信だけを抑制します。AI評価が有効なら、AI呼び出しと利用料金が発生します。AIも呼び出さずに差分だけを確認する場合：

```bash
python3 seclist_diff.py --no-mail --no-ai
```

メール通知を含めて実行する場合：

```bash
python3 seclist_diff.py
```

差分があり、メール設定が有効な場合に送信します。差分がない場合はAI評価・メール送信を行いません。AI評価に失敗した場合は、その旨を本文に記載して差分CSVを添付します。

## 注意事項

- 評価対象は抽出CSVの差分です。既存設定全体を評価するものではありません。
- 行順は無視し、重複行の件数も比較します。値の変更は旧行の削除と新行の追加として記録します。
- AI評価は参考情報です。同一入力でも出力や重要度が変わる場合があり、正確性・安全性・実際の通信可否を保証しません。
- 推定料金はAPIのトークン使用量と設定単価から計算します。モデルを変更する場合は、単価と表示通貨の整合性も確認してください。
