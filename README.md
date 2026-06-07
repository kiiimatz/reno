# Reno

Personal reverse tunnel system.

- **Reno Station** — server (public IP side)
- **Reno Edge** — client (behind NAT/firewall)
- **Dashboard** — Cloudflare Workers web UI

---

## 1. Dashboard のデプロイ (Cloudflare Workers)

### 必要なもの
- Cloudflare アカウント
- Wrangler CLI (`bun install -g wrangler`)

### 手順

```bash
cd dashboard
bun install

# KV namespace を作成
wrangler kv:namespace create RENO_KV
# 出力された id を wrangler.toml の REPLACE_WITH_KV_ID に記入
# preview_id 用も作成
wrangler kv:namespace create RENO_KV --preview
# 出力された id を wrangler.toml の REPLACE_WITH_KV_PREVIEW_ID に記入

# secrets を設定
wrangler secret put USERNAME     # ログインユーザー名
wrangler secret put PASSWORD     # ログインパスワード
wrangler secret put JWT_SECRET   # ランダムな長い文字列
wrangler secret put API_SECRET   # Station/Edge と共有するシークレット

# デプロイ
wrangler deploy
```

デプロイ後、`https://<worker-name>.<account>.workers.dev` でアクセスできます。
カスタムドメインは Cloudflare ダッシュボードの Workers & Pages → Custom Domains から設定。

---

## 2. Reno Station のインストール

### Linux / macOS

```bash
# station のみ
curl -sSL https://raw.githubusercontent.com/kiiimatz/reno/main/install.sh | bash -s station

# edge のみ
curl -sSL https://raw.githubusercontent.com/kiiimatz/reno/main/install.sh | bash -s edge

# 両方
curl -sSL https://raw.githubusercontent.com/kiiimatz/reno/main/install.sh | bash -s both
```

> sudo が必要な場合: `... | sudo bash -s station`

### Windows (PowerShell — 管理者で実行)

```powershell
# station のみ
irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1 | iex; .\install.ps1 station

# edge のみ
irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1 | iex; .\install.ps1 edge

# 両方
irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1 | iex; .\install.ps1 both
```

---

## 3. Station の設定と起動

```bash
# 設定ファイルを作成
cat > station.json << 'EOF'
{
  "name": "tokyo-a",
  "dashboard_url": "https://your-worker.workers.dev",
  "api_secret": "your-api-secret",
  "control_port": 7000
}
EOF

# 起動
reno-station station.json
```

**環境変数でも設定可能:**
```bash
RENO_NAME=tokyo-a \
RENO_DASHBOARD_URL=https://your-worker.workers.dev \
RENO_API_SECRET=your-api-secret \
RENO_CONTROL_PORT=7000 \
reno-station
```

起動すると自動でダッシュボードに登録されます。ダッシュボードの Stations に表示されている ID をメモしてください。

---

## 4. Edge の設定と起動

```bash
# 設定ファイルを作成
cat > edge.json << 'EOF'
{
  "station_id": "STATION_ID_FROM_DASHBOARD",
  "dashboard_url": "https://your-worker.workers.dev",
  "api_secret": "your-api-secret"
}
EOF

# 起動
reno-edge edge.json
```

**環境変数でも設定可能:**
```bash
RENO_STATION_ID=abc123 \
RENO_DASHBOARD_URL=https://your-worker.workers.dev \
RENO_API_SECRET=your-api-secret \
reno-edge
```

---

## 5. トンネルの作成

1. ダッシュボードにログイン
2. **CREATE TUNNEL** で設定:
   - **Station**: 接続したい Station を選択
   - **Protocol**: TCP / HTTP / HTTPS / UDP
   - **IP**: Edge 側のローカル IP（通常 `127.0.0.1`）
   - **Port**: Edge 側の転送したいポート番号
   - **Name**: トンネルの名前
   - **Remote Port**: Station 上で開くポート番号
3. **Create** をクリック

Station が 10 秒以内に設定を取得し、Edge に送信します。  
その後、`station-ip:remote-port` へのアクセスが Edge の `local-ip:local-port` に転送されます。

---

## 6. リリースビルド (開発者向け)

```bash
# タグを打つと GitHub Actions が自動ビルド・リリース
git tag v1.0.0
git push origin v1.0.0

# ローカルでビルド
make build          # 現在のプラットフォーム向け
make release        # 全プラットフォーム向け (dist/ に出力)
```

---

## ファイアウォール設定

Station サーバーで以下のポートを開ける必要があります:

| ポート | 用途 |
|--------|------|
| 7000 (TCP) | Edge からの制御接続 |
| 各トンネルの remote_port | クライアントからのアクセス |
