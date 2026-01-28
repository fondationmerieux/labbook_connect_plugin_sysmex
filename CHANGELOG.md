# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.9.6] - 2026-01-28
### Fixed
- Trim specimen ID before HL7 build to remove left-padded spaces and ensure correct sample matching

## [0.9.5] - 2026-01-12
### Fixed
- Fix GeneXpert mapping to accept integer and float factor values.

## [0.9.4] - 2025-12-23
### Added
- Load LIVD-like mappings at startup and apply them (test/result codes, units, conversions) during ASTM→HL7 OUL^R22 conversion

## [0.9.3] - 2025-12-11
### Added
- Ignore Sysmex BACKGROUNDCHECK QC messages: they are archived but not forwarded to LabBook.
- Added Sysmex ASTM simulation script (RES / CHECK) with proper ENQ/ACK/STX/ETX/EOT framing.

### Fixed
- Correct Sysmex LAB-29 mapping: full OUL^R22 is now generated with PID/SPM/ORC/OBR/OBX.

## [0.9.2] - 2025-12-01
### Fixed
- Added listener shutdown to ensure sockets are properly released on restart and avoid port binding issues.

## [0.9.1] - 2025-10-27
### Added
- Implemented ASTM E1381-02 / E1394-97 LAN communication for Sysmex XP analyzers, including ENQ/ACK/EOT handling, STX/ETX frame processing, and H/P/O/R/L record parsing.

## [0.8.0] - 2025-03-17
### Added
- setting file for Sysmex