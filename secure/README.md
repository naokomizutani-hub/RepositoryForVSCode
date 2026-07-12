# Patched (Secure) Version & Regression Tests

セキュリティレビューで実証された脆弱性に対するパッチ版と、修正前後を比較する
レグレッションテストです。脆弱版（`../app.py` / `../utils.py`）は比較用に
そのまま残してあります。

## 構成

| ファイル | 内容 |
|---|---|
| `secure/app_secure.py` | `app.py` のパッチ版（全エンドポイント修正） |
| `secure/utils_secure.py` | `utils.py` のパッチ版（暗号・コマンド実行修正） |
| `../tests/test_regression.py` | 修正前後の比較テスト（pytest） |
| `../tests/conftest.py` | DB / ダウンロードディレクトリ等の fixture |

## 適用した修正

| 脆弱性 | 修正内容 |
|---|---|
| SQLi (`/login`, `/user`) | プレースホルダによるパラメータ化クエリ。`/user` は整数のみ許可 |
| コマンドインジェクション (`/ping`, `/backup`) | `shell=False`＋引数リスト化、入力の allowlist 検証 |
| 逆シリアライズ (`/load`) | `pickle` を廃止し `json.loads` に変更 |
| パストラバーサル (`/download`) | `realpath` + `commonpath` でベースディレクトリ配下に限定 |
| 反射型 XSS (`/render`, `/login`) | `markupsafe.escape` で出力エスケープ |
| SSRF (`/fetch`) | スキームを http/https に限定、private/loopback IP をブロック |
| オープンリダイレクト (`/redirect`) | 同一サイトの相対パスのみ許可 |
| 弱いセッション鍵 | `secret_key` を環境変数／強乱数から取得 |
| 脆弱なパスワードハッシュ | ソルト付き PBKDF2-HMAC-SHA256（+ `verify_password`） |
| 予測可能な乱数 | `secrets.token_hex` に変更 |
| 固定 IV / ハードコード鍵 | 呼び出しごとにランダム IV、鍵は環境変数から取得 |
| 非定数時間比較 | `hmac.compare_digest` に変更 |
| 脆弱なハッシュ (SHA-1) | SHA-256 に変更 |
| debug モード | `debug=False`、既定でループバックにバインド |

## テスト実行

```bash
pip install flask requests pycryptodome pytest
pytest -v tests/test_regression.py
```

各テストは同一の攻撃ペイロードを脆弱版とパッチ版の両方に送り、
**脆弱版では悪用成功／パッチ版ではブロック**されることをアサートします。

### 検証済み結果

```
14 passed
```
