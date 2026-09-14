# Sysmex – LabBook Connect plugin

This plugin enables communication between a Sysmex analyzer and LabBook.
The analyzer communicates using ASTM only, HL7 being used toward the LIS alone.

## Installation note

This bundle is NOT a ready-to-use directory.

Files must be installed individually, either:
- by copying them manually to their corresponding locations on the server, or
- by uploading them through the LabBook user interface (when supported).

The analyzer setting file is a sample and MUST be edited before use
(network parameters, analyzer ID, URLs).

Do not deploy the bundle as a single directory.

## Compatible models

| Models | Transactions |
|---|---|
| XN series | query, orders and results |
| XP series | query and results, the series does not accept orders from the LIS |

Based on the ASTM communication specifications of both series.

## Communication protocols

- Analyzer ↔ LabBook Connect: ASTM E1381 over TCP socket, as specified in the Sysmex XP series
  and XN series ASTM communication specifications (ASTM E1394-97 over E1381-02)
- LabBook Connect ↔ LIS: HL7 v2.5.1 (HTTP)

## Supported transactions

- LAB-27 (Query)  
  ASTM Q| (analyzer) → HL7 QBP^Q11 (to LIS)  
  HL7 RSP^K11 (from LIS) → ASTM (to analyzer)

- LAB-28 (Orders)  
  HL7 OML^O33 (from LIS) → ASTM (to analyzer)

- LAB-29 (Results)  
  ASTM (from analyzer) → HL7 OUL^R22 (to LIS)

Test orders sent to the analyzer, LAB-27 and LAB-28, follow the XN series layout. The XP series
does not accept orders from the host, its whole "Host computer to analyzer" column reads
"Not used", so only results reach the LIS on that series.

## Deployment modes

- server (validated, production mode)  
  LabBook Connect listens on a TCP port and waits for the analyzer connection.

- client (experimental)  
  LabBook Connect connects to the analyzer IP/port.  
  Not recommended for production use.

## Configuration files

Two configuration files are required for each Sysmex analyzer instance:
- one analyzer setting file (connection and routing)
- one mapping file (tests and result mapping)

### 1) Analyzer settings

Location:  
    /storage/resource/connect/analyzer/setting/

Sample file:  
    doc/analyzer_sysmex.toml

Important:
- The operator MUST edit this file before use.
- In server mode, the ip field is ignored.
- In client mode (experimental), the ip field is required.
- Allowed TCP port ranges:
  - 7500–7599
  - 12300–12399

### 2) Mapping file

Location:  
    /storage/resource/connect/analyzer/mapping/

Sample file:  
    doc/mapping_sysmex.toml

Notes:
- Only tests explicitly listed are supported.
- Additional tests and result mappings must be added as needed.

## Logging

- Logs use the global LabBook Connect logging configuration.
- Low-level ASTM traffic (ENQ, ACK, frames) is logged for diagnostic purposes.

## Message archiving

Message archiving is controlled by the `archive_msg` setting in the analyzer configuration file.

When enabled (`archive_msg = "Y"`), raw messages are archived on disk for traceability and diagnostics.

Archived messages are stored per analyzer instance in:
    /storage/resource/connect/analyzer/{id_analyzer}/

Subdirectories:
- archive_lab27 (LAB-27 queries)
- archive_lab28 (LAB-28 orders)
- archive_lab29 (LAB-29 results)

Messages are saved as plain text files.
Filenames include the transaction type, message source (Analyzer or LIS), and a timestamp.

## Testing without an instrument

`script/simulate_sysmex.py` plays the part of the instrument. It connects to the plugin the way
an analyzer does, speaks ASTM E1381 in both directions, and reports what the plugin answered.

```bash
python3 script/simulate_sysmex.py --host <connect host> --port <analyzer port> \
        --scenario results --specimen 1535
```

The port is the one set in the analyzer settings file, not a fixed value.

| Scenario | What the instrument sends | What it checks |
|---|---|---|
| `results` | a complete blood count, 40 analytes over 11 frames | multi-frame splitting, mapping of every analyte |
| `qc` | a BACKGROUNDCHECK quality control run | that it is archived and not forwarded to the LIS |
| `query` | an order request | that the sample number is extracted from the composite field |

The result values come from a real XN-350 trace. The analyte list follows the mapping file, not
the LIS referential: an analyte that does not reach the record points at a `lis_result_code` with
no matching `code_var` on that installation.

The script also checks the reply and warns when something does not follow the specification:
frame numbers out of order, wrong checksums, a termination code other than the one expected.

Two options help during troubleshooting. `--nak-frame N` rejects frame N once, so that the plugin
has to send it again. `--verbose` prints the raw frames.

## Limitations

- Client mode is experimental.

## Versioning

- Plugin version is embedded in the JAR.
- Setting and mapping files have independent versions.
