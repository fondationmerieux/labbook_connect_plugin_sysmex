# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.9.2] - 2025-12-01
### Fixed
- Added listener shutdown to ensure sockets are properly released on restart and avoid port binding issues.

## [0.9.1] - 2025-10-27
### Added
- Implemented ASTM E1381-02 / E1394-97 LAN communication for Sysmex XP analyzers, including ENQ/ACK/EOT handling, STX/ETX frame processing, and H/P/O/R/L record parsing.

## [0.8.0] - 2025-03-17
### Added
- setting file for Sysmex