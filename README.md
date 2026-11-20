# llmhub (llm backend)

## 1. Install on the VPS (once)
```
scp llmhub-linux-amd64 vps:/usr/local/bin/llmhub && ssh vps chmod +x /usr/local/bin/llmhub
scp llmhub.service vps:/etc/systemd/system/
```
`/etc/llmhub.env` (chmod 600):
```
HUB_LISTEN=127.0.0.1:8100
HUB_ADMIN_KEY=<long secret, goes into the notebooks as HUB_KEY>
HUB_API_KEYS=<key for omp>,<another key if you want>
PORT_MIN=9001
PORT_MAX=9099
```
`systemctl daemon-reload && systemctl enable --now llmhub`
(no Go needed on the VPS; to rebuild: `CGO_ENABLED=0 go build -ldflags="-s -w" -o llmhub .`)

## 2. Caddy: point llm at the hub instead of tunnel port 9001
```
llm.example.com {
    reverse_proxy 127.0.0.1:8100 {
        flush_interval -1
    }
}
```
`systemctl reload caddy`

## 3. chisel: allow the whole port range
In /etc/chisel/users.json widen the reverse-remote regex you have now (it matches `R:127.0.0.1:9001`)
so it covers the range, e.g. `^R:127\.0\.0\.1:90[0-9][0-9]$`.

## 4. Notebooks
Each notebook: unique `SERVER_NAME` (sr1, sr2...), `HUB_KEY` = HUB_ADMIN_KEY. Run top to bottom.
Ports are automatic; the same name always gets the same tunnel port back.

## 5. Clients (omp etc.)
base URL `https://llm.example.com/v1`, API key = one of HUB_API_KEYS, model `sr1/model1`.
List: `GET /v1/models` (add `?all=1` to see offline ones). Status: `GET /_hub/servers`.

## How the 120 s problem is handled
- Response headers go out immediately; while the model is silent the hub sends `: keepalive` (SSE)
  or a space (non-stream JSON) every 15 s.
- The job keeps running if your client drops. The same request again (same body, or same
  `Idempotency-Key` header) re-attaches and replays from the start. Header `X-Hub-Job` holds the id;
  `GET /v1/jobs/<id>?offset=N` resumes by hand. `X-No-Cache: 1` forces a fresh run.
- A job nobody re-attached to is cancelled after 10 min (ORPHAN_GRACE); results are kept 30 min (JOB_TTL),
  identical requests are answered from the stored result for 5 min (REPLAY_WINDOW).
- Storage is in memory (no Redis): a hub restart drops running jobs, the retry then starts fresh.
- Same model on two notebooks: requests for the bare model name go to the less busy one.
