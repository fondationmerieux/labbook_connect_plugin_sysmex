#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASTM E1381 minimal server for Sysmex.
- Listens on a TCP port
- Implements ENQ/ACK handshakes, frame ACK/NAK, and EOT handling
- Verifies 2-hex checksum (sum of bytes between STX and ETX/ETB, including frame number)
- Logs hex + ASCII + protocol events to a rotating log file
- Optionally writes the raw ASTM payload (records) to an output file

Usage:
  python astm_server.py --port 12345 --log astm_server.log --capture out.astm

Notes:
- Timeouts are conservative to keep the session responsive.
- If checksum fails, server sends NAK and logs the error.
- Works well to “sniffer”.
"""

import argparse
import logging
import logging.handlers
import socket
import sys
import time
from datetime import datetime

# ASCII control characters
ENQ = 0x05
ACK = 0x06
NAK = 0x15
EOT = 0x04
STX = 0x02
ETX = 0x03
ETB = 0x17
CR  = 0x0D
LF  = 0x0A

READ_TIMEOUT_S = 15.0   # timeout socket read
IDLE_TIMEOUT_S = 120.0  # end of session if nothing happens

def hexdump(b: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hexs = " ".join(f"{x:02X}" for x in chunk)
        text = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append(f"{i:04X}  {hexs:<{width*3}}  {text}")
    return "\n".join(lines)

def calc_checksum(frame_bytes: bytes) -> int:
    """
    ASTM checksum = low 8 bits of sum of all bytes from (and including) the
    frame number up to (and including) ETX/ETB. STX is excluded.
    """
    return sum(frame_bytes) & 0xFF

def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)

def recv_until(sock: socket.socket, stop_bytes: set, max_len: int = 8192) -> bytes:
    """
    Read bytes until one of stop bytes encountered or max_len exceeded.
    Returns the data INCLUDING the stop byte.
    """
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            return bytes(buf)
        buf.extend(b)
        if b[0] in stop_bytes or len(buf) >= max_len:
            return bytes(buf)

def setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("astm_server")
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
            )
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    # also echo to console (info+)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    return logger

def dump_full_message(logger: logging.Logger, full_message: bytearray, capture_fh):
    """
    After EOT / session end, dump the full reconstructed ASTM message in readable ASCII,
    and also persist it to --capture if requested.
    """
    try:
        ascii_msg = full_message.decode("ascii", errors="replace")
    except Exception:
        ascii_msg = repr(full_message)

    logger.info("===== MESSAGE ASTM COMPLET (début) =====")
    # For readability in logs: show each CR as newline
    logger.info(ascii_msg.replace("\r", "\r\n"))
    logger.info("===== MESSAGE ASTM COMPLET (fin) =====")

    if capture_fh:
        capture_fh.write(b"\n##### NEW MESSAGE #####\n")
        capture_fh.write(full_message)
        capture_fh.write(b"\n##### END MESSAGE #####\n")
        capture_fh.flush()

def handle_client(conn: socket.socket, addr, logger: logging.Logger, capture_fh):
    # buffer to reconstruct the full ASTM message across multiple frames
    full_message = bytearray()

    conn.settimeout(READ_TIMEOUT_S)
    peer = f"{addr[0]}:{addr[1]}"
    logger.info(f"Client connected: {peer}")

    last_activity = time.time()
    try:
        while True:
            # Idle timeout
            if time.time() - last_activity > IDLE_TIMEOUT_S:
                logger.info("Idle timeout reached; closing session.")
                # dump whatever we got so far (might be partial)
                dump_full_message(logger, full_message, capture_fh)
                return

            # Read one byte (expect ENQ, or EOT if remote aborts)
            try:
                b = conn.recv(1)
            except socket.timeout:
                continue

            if not b:
                logger.info("Connection closed by peer.")
                # dump partial message before exit
                dump_full_message(logger, full_message, capture_fh)
                return

            last_activity = time.time()
            byte = b[0]

            if byte == ENQ:
                logger.info("<<< ENQ received — sending ACK")
                conn.sendall(bytes([ACK]))
                continue

            if byte == EOT:
                logger.info("<<< EOT received — session complete")
                # here is where we dump the full reconstructed ASTM message
                dump_full_message(logger, full_message, capture_fh)
                return

            if byte == STX:
                # Read one ASTM frame:
                # STX already read; now read until ETX or ETB is included.
                # Format: STX <frame-no> <text> <ETX|ETB> <cksum(2 hex chars)> <CR> <LF>
                frame = bytearray()
                # we will build the checksum input (from frame-no up to ETX/ETB)
                checksum_input = bytearray()

                # first byte after STX is the frame number
                frame_no_b = conn.recv(1)
                if not frame_no_b:
                    logger.warning("Frame aborted: no frame number.")
                    # dump and bail, so we don't lose what we had
                    dump_full_message(logger, full_message, capture_fh)
                    return
                frame.extend(frame_no_b)
                checksum_input.extend(frame_no_b)

                # then read until ETX or ETB
                data = recv_until(conn, {ETX, ETB})
                if not data or data[-1] not in (ETX, ETB):
                    logger.warning("Frame aborted: ETX/ETB not found.")
                    dump_full_message(logger, full_message, capture_fh)
                    return
                frame.extend(data)
                checksum_input.extend(data)

                # read checksum (2 ASCII hex)
                cks = read_exact(conn, 2)
                if len(cks) != 2:
                    logger.warning("Frame aborted: missing 2-digit checksum.")
                    dump_full_message(logger, full_message, capture_fh)
                    return

                # read CR LF
                crlf = read_exact(conn, 2)
                if len(crlf) != 2 or crlf[0] != CR or crlf[1] != LF:
                    logger.warning(f"Frame aborted: missing CRLF (got {crlf!r}).")
                    dump_full_message(logger, full_message, capture_fh)
                    return

                # full frame (for debug hex dump)
                full = bytes([STX]) + bytes(frame) + cks + crlf
                logger.debug("<<< Received frame\n" + hexdump(full))

                # verify checksum
                calc = calc_checksum(bytes(checksum_input))
                try:
                    recv_ck = int(cks.decode("ascii"), 16)
                except Exception:
                    recv_ck = -1
                ok = (recv_ck == calc)

                # extract payload = text between frame-no and ETX/ETB (exclude frame-no byte and terminator)
                payload = bytes(frame[1:-1])

                # prepare human-readable payload for logs
                safe = payload.decode("ascii", errors="replace")

                # frame number pretty print
                frame_no_val = frame[0]
                frame_no_disp = chr(frame_no_val) if 32 <= frame_no_val <= 126 else frame_no_val
                logger.info(
                    f"Frame #{frame_no_disp} "
                    f"len={len(payload)} checksum=recv:{recv_ck:02X} calc:{calc:02X} "
                    f"status={'OK' if ok else 'BAD'}"
                )
                logger.debug(f"Payload (ASCII): {safe}")

                # append to capture file (raw ASTM records, with CR at end)
                if capture_fh:
                    if payload.endswith(b"\r"):
                        capture_fh.write(payload)
                    else:
                        capture_fh.write(payload + b"\r")
                    capture_fh.flush()

                # append to reconstructed full message if checksum is OK
                if ok:
                    full_message.extend(payload)
                    # optional safety: ensure CR separator if frame didn't end with CR
                    if not payload.endswith(b"\r"):
                        full_message.extend(b"\r")

                # ACK/NAK frame
                if ok:
                    logger.info(">>> Sending ACK for frame")
                    conn.sendall(bytes([ACK]))
                else:
                    logger.warning(">>> Sending NAK (checksum mismatch)")
                    conn.sendall(bytes([NAK]))
                continue

            # If we get ACK/NAK from peer (shouldn’t in server role, but log it)
            if byte == ACK:
                logger.info("<<< ACK from peer (unexpected in server role)")
                continue
            if byte == NAK:
                logger.info("<<< NAK from peer (unexpected in server role)")
                continue

            # Any other control—log and continue
            logger.debug(f"<<< Unexpected byte 0x{byte:02X}; ignoring")

    except socket.timeout:
        logger.info("Socket timeout; closing session.")
        dump_full_message(logger, full_message, capture_fh)
    except Exception as e:
        logger.exception(f"Error during client handling: {e}")
        dump_full_message(logger, full_message, capture_fh)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        logger.info(f"Client disconnected: {peer}")

def main():
    parser = argparse.ArgumentParser(description="ASTM E1381 server (Sysmex capture).")
    parser.add_argument("--port", type=int, required=True, help="TCP port to listen on.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0).")
    parser.add_argument("--log", default=None, help="Path to log file (default: astm_server_YYYYmmdd.log).")
    parser.add_argument("--capture", default=None, help="Optional path to write raw ASTM payload (records).")
    args = parser.parse_args()

    log_path = args.log or f"astm_server_{datetime.now().strftime('%Y%m%d')}.log"
    logger = setup_logger(log_path)
    logger.info(f"Starting ASTM server on {args.host}:{args.port}")

    capture_fh = None
    try:
        if args.capture:
            capture_fh = open(args.capture, "ab", buffering=0)
            logger.info(f"Capturing payload to: {args.capture}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((args.host, args.port))
            s.listen(5)
            logger.info("Waiting for connections...")
            while True:
                conn, addr = s.accept()
                handle_client(conn, addr, logger, capture_fh)
                logger.info("Ready for next connection.")
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    finally:
        if capture_fh:
            capture_fh.close()
        logger.info("Server stopped.")

if __name__ == "__main__":
    main()

