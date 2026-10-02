# Running scanners locally (Linux / WSL2 Ubuntu)

Run from the repo root in bash (Linux, or Ubuntu under WSL2). Keep the repo inside the Linux filesystem (e.g. `~/repos/...`), not under `/mnt/c/`, because bind mounts from the Windows side are slow and mess up file permissions. Put all output in `reports/`. Pin image tags to exact versions.

```bash
mkdir -p reports
docker build -t juice-shop:local ./app
docker run -d --rm -p 3000:3000 --name juice juice-shop:local

docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:<ver> git /repo --report-format sarif --report-path /repo/reports/gitleaks.sarif
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports:/out" aquasec/trivy:<ver> image --scanners vuln --format json -o /out/trivy-image.json juice-shop:local
docker run --rm -v "$PWD:/src" aquasec/trivy:<ver> fs --scanners vuln --format json -o /src/reports/trivy-fs.json /src/app
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:<ver> semgrep scan --config p/default --sarif -o reports/semgrep.sarif app
docker run --rm -v "$PWD:/src" bridgecrew/checkov:<ver> -d /src --framework dockerfile github_actions -o sarif --output-file-path /src/reports
docker run --rm --add-host=host.docker.internal:host-gateway -v "$PWD/reports:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:<ver> zap-baseline.py -t http://host.docker.internal:3000 -J zap.json

python3 triage/triage.py reports/ --policy triage/waivers.yaml
```

Notes for Linux:

- `--add-host=host.docker.internal:host-gateway` makes the ZAP container reach Juice Shop on the host. Linux Docker Engine doesn't define `host.docker.internal` by default.
- Containers that write into `reports/` may create root-owned files. Add `--user "$(id -u):$(id -g)"` where the image supports it, or `sudo chown -R "$USER" reports/` afterwards. ZAP writes as its own `zap` user (UID 1000), so `reports/` must be writable by it.
