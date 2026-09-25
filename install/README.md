# Installation — SYSMEX plugin for LabBook Connect

This folder contains everything needed to connect a **SYSMEX** analyzer to LabBook through LabBook Connect.

| File | Role | Destination on the server |
|---|---|---|
| `AnalyzerSysmex.jar` | Plugin (compiled Java) | `/storage/resource/connect/analyzer/plugin/` |
| `analyzer_sysmex.toml` | Settings file: analyzer identity and connection | `/storage/resource/connect/analyzer/setting/` |
| `mapping_sysmex.toml` | Mapping between analyzer test codes and LabBook variables | `/storage/resource/connect/analyzer/mapping/` |

Connection: **ASTM** messages over TCP socket (**E1381** low-level protocol). LabBook Connect listens (`server` mode); the analyzer connects to it.

---

## 1. Before you start

Collect the following information:

- The analyzer **model** (e.g. XN-550, XN-1000…) and its **serial number**.
- The **IP address** of the analyzer on the laboratory network.
- A free **TCP port** on the LabBook server (e.g. `7502`). It must be different from the ports used by other analyzers.
- The **LabBook analysis and variable codes** that will receive the results (e.g. the CBC / NFS analysis).

---

## 2. Fill in the settings file

Open `analyzer_sysmex.toml` in a text editor and replace **every** `XXXX` / `X.X.X.X` value.

```toml
version = "0.9.1"

[analyzer]
brand = "SYSMEX"
name = "XN-550"                      # Analyzer model
id = "SYSMEX_01"                     # Unique identifier — same value as in LabBook
plugin = "AnalyzerSysmex"            # Do not change
url_lis = "http://localhost/sigl"    # LabBook address seen from LabBook Connect
operation_mode = "query"
archive_msg = "Y"
type_cnx = "socket_E1381"            # Do not change
type_msg = "ASTM"                    # Do not change
mapping = "/storage/resource/connect/analyzer/mapping/mapping_sysmex"

[analyzer.socket]
mode = "server"                      # LabBook Connect listens, the analyzer connects
ip = "192.168.1.50"                  # Analyzer IP address
port = 7502                          # Listening port (number, no quotes)
```

| Key | What to enter |
|---|---|
| `name` | Analyzer model |
| `id` | Short unique identifier with no spaces, e.g. `SYSMEX_01`. You will enter **exactly the same value** in LabBook (step 4). |
| `url_lis` | Leave `http://localhost/sigl` when LabBook and LabBook Connect run on the same server. |
| `ip` | IP address of the analyzer |
| `port` | TCP port, written as a **number without quotes** |
| `mapping` | Path to the mapping file. Leave as is if you keep the default location. |

Do not modify `plugin`, `type_cnx` and `type_msg`.

> ⚠️ **Never leave a placeholder value (`XXXX`, `X.X.X.X`) in a file placed in the `setting/` folder.**
> LabBook reads every file in that folder. A single invalid file prevents **all** analyzers from loading, not only this one.

---

## 3. Copy the files to the server

```bash
cp AnalyzerSysmex.jar     /storage/resource/connect/analyzer/plugin/
cp analyzer_sysmex.toml   /storage/resource/connect/analyzer/setting/
cp mapping_sysmex.toml    /storage/resource/connect/analyzer/mapping/
```

Then **restart LabBook Connect**. The plugin (`.jar`) is only loaded at startup; restarting LabBook alone is not enough.

---

## 4. Declare the analyzer in LabBook

1. In LabBook, open the analyzer management page and add a new analyzer.
2. Enter the **same identifier** as `id` in the settings file (e.g. `SYSMEX_01`).
3. Set the **Mode**:
   - **Query**: LabBook sends nothing on its own; the analyzer asks LabBook for the tests to perform after reading the sample barcode.
   - **Batch**: LabBook sends the test request to the analyzer each time a sample is created.

   Choose the mode according to how the analyzer is configured (host query or not). If in doubt, use **Query**.

> The `operation_mode` key in the settings file has no effect on behavior. The **Mode of the analyzer record in LabBook** is the setting that counts.

---

## 5. Configure the analyzer

In the analyzer's host/LIS communication settings:

| Setting | Value |
|---|---|
| Protocol | ASTM |
| Host IP address | IP address of the LabBook server |
| Host port | Same value as `port` in the settings file |

Enable automatic result transmission, and host query if you chose the **Query** mode.

---

## 6. Adapt the mapping

`mapping_sysmex.toml` links each analyzer parameter (WBC, RBC, HGB…) to a **LabBook variable code**.

Check that every code in the mapping exists in your LabBook analysis. If a code does not exist, the result is received but **no field is pre-filled**.

The mapping is reloaded without restarting LabBook Connect.

---

## 7. Check that it works

1. Look at the log:
   ```bash
   tail -f /var/log/labbook/connect/labbook_connect.log
   ```
   After the restart, the log must show that the analyzer is loaded and listening on the chosen port.
2. Run a sample on the analyzer.
3. In LabBook, check that the message appears in **Transactions** and that the results are pre-filled in the analysis.

## Troubleshooting

| Symptom | Check |
|---|---|
| No analyzer loads at all | A file in `setting/` is invalid (placeholder value, syntax error). |
| LabBook answers "analyzer not added" | `plugin = "AnalyzerSysmex"` spelled exactly, and LabBook Connect restarted after copying the `.jar`. |
| The analyzer reports a communication failure | IP address and port on the analyzer, firewall, port not used by another analyzer. |
| Results received but not pre-filled | Codes in the mapping do not match the LabBook variable codes. |
