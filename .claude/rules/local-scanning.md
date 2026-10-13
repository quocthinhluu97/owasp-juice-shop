# Running scanners locally (Linux / WSL2 Ubuntu)

Run from the repo root in bash (Linux, or Ubuntu under WSL2). Keep the repo inside the Linux filesystem (e.g. `~/repos/...`), not under `/mnt/c/`, because bind mounts from the Windows side are slow and mess up file permissions. Put all output in `reports/`. Pin image tags to exact versions.

```bash
mkdir -p reports
docker build -t juice-shop:local ./app
docker run -d --rm -p 127.0.0.1:3000:3000 --name juice juice-shop:local

docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:<ver> git /repo --report-format sarif --report-path /repo/reports/gitleaks.sarif   # exploration only; CI's hashed JSON is what triage reads (see security.yml)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports:/out" aquasec/trivy:<ver> image --scanners vuln --format json -o /out/trivy-image.json juice-shop:local
docker run --rm -v "$PWD:/src" aquasec/trivy:<ver> fs --scanners vuln --format json -o /src/reports/trivy-fs.json /src/app
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:<ver> semgrep scan --config p/default --sarif -o reports/semgrep.sarif app
mkdir -p reports/checkov
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/src:ro" -v "$PWD/reports/checkov:/out" bridgecrew/checkov:<ver> -d /src --config-file /src/.checkov.yaml --soft-fail -o cli -o json -o sarif --output-file-path console,/out/results_json.json,/out/results_sarif.sarif
python3 triage/triage.py reports/ --policy triage/waivers.yaml
```

ZAP baseline (phase 6) runs on its own network, with the pinned add-on. Stop the `juice` container from the block above first, since both use the name `juice`:

```bash
ZAP=ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2
ZAP_BETA_SHA256=a979f7cd5d8be10e0338b417e006ec1e2f6ec79101010d570ddb5199892e921b

# Add-on (pscanrulesBeta v50, 6 rules): kept outside the repo, downloaded once, hash-checked each run.
ADDON_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/zap-addons"
ADDON="$ADDON_DIR/pscanrulesBeta-beta-50.zap"
mkdir -p "$ADDON_DIR"
curl -fsSL -o "$ADDON" https://github.com/zaproxy/zap-extensions/releases/download/pscanrulesBeta-v50/pscanrulesBeta-beta-50.zap
echo "$ZAP_BETA_SHA256  $ADDON" | sha256sum -c -

mkdir -p reports/zap
cp .zap/rules.tsv reports/zap/      # -c is relative to /zap/wrk, so the rules file goes into the mounted dir
# bash (uses ${PIPESTATUS[0]} below). Run from the repo root.
# Remove a leftover `scan` network first: one created without --internal would give ZAP internet egress.
docker network rm scan 2>/dev/null || true
docker network create --internal scan   # --internal: no internet egress for either container
# Guard: if this prints, stop here (rm failed, e.g. something still attached). Safe to paste: it doesn't exit the shell.
[ "$(docker network inspect -f '{{.Internal}}' scan)" = true ] || { echo "scan network is not internal: stop here" >&2; false; }
docker run -d --rm --network scan --name juice juice-shop:local
until docker run --rm --network scan "$ZAP" curl -sf --max-time 5 -o /dev/null http://juice:3000/; do sleep 3; done
docker run --rm --network scan -v "$PWD/reports/zap:/zap/wrk:rw" \
  -v "$ADDON:/zap/plugin/pscanrulesBeta-beta-50.zap:ro" \
  "$ZAP" zap-baseline.py -t http://juice:3000 -j -z "-silent" -c rules.tsv -J zap.json -r zap.html 2>&1 \
  | tee reports/zap/zap-console.txt
echo "exit ${PIPESTATUS[0]}"   # 0 clean, 1 a FAIL rule fired, 2 WARN only; anything else is an error
docker stop juice; docker network rm scan
```

Notes for Linux:

- Always publish the app on `127.0.0.1` only. Plain `-p 3000:3000` listens on every interface and exposes the deliberately vulnerable app to the local network.
- If host port 3000 is taken (check `docker ps` and `ss -ltn`), map another host port, e.g. `-p 127.0.0.1:3001:3000`. On the user's machine a Grafana container from another project holds 3000; don't stop it.
- ZAP doesn't use a published port. Both steps above run on the `scan` network and ZAP targets `http://juice:3000`. `--internal` matters: without it the Client Spider followed an open redirect out to GitHub (see `docs/findings/zap.md`).
- The add-on isn't in the repo and Dependabot can't see it. When you bump the ZAP image, check the zap-extensions releases for a pscanrulesBeta that supports the new ZAP version, then update the URL and SHA-256 here and `ZAP_BETA_URL` / `ZAP_BETA_SHA256` in `security.yml`. Without `-z "-silent"` the scan tries to download add-ons and fails on the internal network.
- Containers that write into `reports/` may create root-owned files. Add `--user "$(id -u):$(id -g)"` where the image supports it, or `sudo chown -R "$USER" reports/` afterwards. ZAP writes as its own `zap` user (UID 1000), so `reports/zap/` must be writable by it.
