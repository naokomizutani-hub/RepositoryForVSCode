# Vulnerable Demo App (セキュリティスキャン検証用)

> ⚠️ **注意 / WARNING**
> このリポジトリのコードは、Claude Security（security-review）などの
> セキュリティスキャナーの動作検証を目的として、**意図的に脆弱性を含めて**
> 作成されています。本番環境では絶対に使用しないでください。
>
> This code intentionally contains security vulnerabilities for the sole
> purpose of testing/validating security scanning tooling. **Do NOT deploy.**

## 含まれる想定脆弱性 / Intended vulnerabilities

- SQL Injection（文字列連結によるクエリ組み立て）
- OS Command Injection（`os.system` / `subprocess shell=True`）
- Path Traversal（ユーザー入力を用いたファイルパス）
- Cross-Site Scripting (XSS)（エスケープなしの HTML 出力）
- Hardcoded Secrets（ソース内にAPIキー・パスワードを直書き）
- Weak Cryptography（MD5 / 固定 IV）
- Insecure Deserialization（`pickle.loads`）
- Server-Side Request Forgery (SSRF)
- Insecure Randomness（トークン生成に `random` を使用）

## 構成

- `app.py` — 上記脆弱性を含む Flask アプリ
- `utils.py` — 補助的な脆弱コード
