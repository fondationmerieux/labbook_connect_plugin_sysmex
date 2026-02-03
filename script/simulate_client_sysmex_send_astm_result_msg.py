#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
from typing import List

# ASTM control characters
ENQ = 0x05
ACK = 0x06
NAK = 0x15
EOT = 0x04
STX = 0x02
ETX = 0x03
CR = 0x0D
LF = 0x0A


def printable(byte_val: int) -> str:
    """Return a human readable representation for debug."""
    if 32 <= byte_val <= 126:
        return f"'{chr(byte_val)}'"
    mapping = {
        ENQ: "ENQ",
        ACK: "ACK",
        NAK: "NAK",
        EOT: "EOT",
        STX: "STX",
        ETX: "ETX",
        CR: "CR",
        LF: "LF",
    }
    return mapping.get(byte_val, f"0x{byte_val:02X}")


def build_frames(astm_message: str) -> List[bytes]:
    """
    Build ASTM E1381 frames for a logical ASTM message.

    Input message must contain CR as record separator (H|, P|, O|, R|, L|...).
    This mimics AnalyzerSysmex.sendASTMMessage().
    """
    msg_norm = astm_message.replace("\r\n", "\r").replace("\n", "\r")
    lines = [line for line in msg_norm.split("\r") if line]

    frames: List[bytes] = []

    for idx, line in enumerate(lines):
        # Frame number cycles 1..7,0
        frame_no = (idx + 1) % 8
        if frame_no == 0:
            frame_char = b"0"
        else:
            frame_char = bytes([ord("0") + frame_no])

        # Body = frameNo + record line + CR  <-- IMPORTANT
        body = frame_char + line.encode("ascii", errors="replace") + b"\r"

        checksum = (sum(body) + ETX) & 0xFF
        checksum_str = f"{checksum:02X}".encode("ascii")

        frame = bytes([STX]) + body + bytes([ETX]) + checksum_str + bytes([CR, LF])
        frames.append(frame)

    return frames


def send_astm_message(sock: socket.socket, astm_message: str) -> None:
    """Send one ASTM message as analyzer (client) to the plugin."""
    print(">>> Sending ENQ")
    sock.sendall(bytes([ENQ]))

    resp = sock.recv(1)
    if not resp:
        raise RuntimeError("No response after ENQ")
    if resp[0] != ACK:
        raise RuntimeError(f"Unexpected response after ENQ: {printable(resp[0])}")
    print("<<< Received ACK after ENQ")

    frames = build_frames(astm_message)

    for i, frame in enumerate(frames, start=1):
        print(f">>> Sending frame {i}/{len(frames)}")
        sock.sendall(frame)

        r = sock.recv(1)
        if not r:
            raise RuntimeError(f"No response after frame {i}")
        if r[0] == ACK:
            print(f"<<< Frame {i} ACK")
        elif r[0] == NAK:
            raise RuntimeError(f"Frame {i} got NAK from plugin")
        else:
            raise RuntimeError(f"Frame {i} unexpected response: {printable(r[0])}")

    print(">>> Sending EOT (end of message)")
    sock.sendall(bytes([EOT]))


def receive_astm_from_plugin(sock: socket.socket) -> str:
    """
    Receive ASTM response from plugin (host -> analyzer direction).

    Minimal behavior:
    - Wait ENQ, answer ACK
    - Receive frames, always ACK them
    - Stop on EOT and return assembled payload as string
    """
    sock.settimeout(10.0)

    print("\n--- Waiting for response from plugin ---")
    # Wait for ENQ
    while True:
        b = sock.recv(1)
        if not b:
            print("Connection closed while waiting for ENQ")
            return ""
        if b[0] == ENQ:
            print("<<< ENQ from plugin")
            break
        else:
            print("Ignoring byte while waiting for ENQ:", printable(b[0]))

    print(">>> Sending ACK for ENQ")
    sock.sendall(bytes([ACK]))

    assembled = bytearray()

    while True:
        b = sock.recv(1)
        if not b:
            print("Connection closed while waiting for STX/EOT")
            return assembled.decode("ascii", errors="replace")

        if b[0] == EOT:
            print("<<< EOT from plugin (response complete)")
            break

        if b[0] != STX:
            print("Unexpected byte while waiting for STX/EOT:", printable(b[0]))
            continue

        frame_no_b = sock.recv(1)
        if not frame_no_b:
            raise RuntimeError("Stream closed after STX while reading frame number")
        frame_no = frame_no_b[0]
        print(f"<<< STX, frame {chr(frame_no)}")

        payload = bytearray()
        while True:
            c = sock.recv(1)
            if not c:
                raise RuntimeError("Stream closed while reading frame payload")
            if c[0] == ETX:
                break
            payload.extend(c)

        chk = sock.recv(2)
        trailer = sock.recv(2)
        if len(chk) < 2 or len(trailer) < 2:
            raise RuntimeError("Incomplete frame trailer from plugin")

        print("<<< Received frame payload length:", len(payload))
        assembled.extend(payload)

        sock.sendall(bytes([ACK]))
        print(">>> Sent ACK for frame")

    msg = assembled.decode("ascii", errors="replace")
    msg = msg.replace("\r\n", "\r").strip()
    return msg


def get_sysmex_result_message(specimen: str) -> str:
    """
    Build a minimal but realistic Sysmex LAB-29 patient result message.
    Specimen ID is injected in the O-record.
    """
    segments = [
        "H|\\^&|||    XN-350^00-27^15735^^^^AW618382||||||||E1394-97",
        "P|1",
        "C|1||",
        f"O|1||^^{specimen}^A|^^^^WBC\\^^^^RBC\\^^^^HGB\\^^^^HCT\\^^^^PLT|||||||N||||||||||||||F",
        "R|1|^^^^WBC^26|7.4|10^3/uL||N|||OP1||20251205133500",
        "R|2|^^^^RBC^27|4.45|10^6/uL||N|||OP1||20251205133500",
        "R|3|^^^^HGB^28|13.2|g/dL||N|||OP1||20251205133500",
        "R|4|^^^^HCT^29|40.1|%||N|||OP1||20251205133500",
        "R|5|^^^^PLT^30|250|10^3/uL||N|||OP1||20251205133500",
        "L|1|N",
    ]
    return "\r".join(segments) + "\r"


def get_sysmex_background_check_message() -> str:
    """
    Build a Sysmex LAB-29 Background Check message.

    Specimen ID is BACKGROUNDCHECK so that AnalyzerSysmex
    detects it and does not send HL7 upstream.
    """
    segments = [
        "H|\\^&|||    XN-350^00-27^15735^^^^AW618382||||||||E1394-97",
        "P|1",
        "C|1||",
        "O|1||^^BACKGROUNDCHECK^A|^^^^WBC\\^^^^RBC\\^^^^HGB\\^^^^HCT\\^^^^PLT|||||||Q||||||||||||||F",
        "R|1|^^^^WBC^26|7.0|10^3/uL||N|||QC1||20251205120400",
        "R|2|^^^^RBC^27|4.50|10^6/uL||N|||QC1||20251205120400",
        "R|3|^^^^HGB^28|13.0|g/dL||N|||QC1||20251205120400",
        "R|4|^^^^HCT^29|39.8|%||N|||QC1||20251205120400",
        "R|5|^^^^PLT^30|240|10^3/uL||N|||QC1||20251205120400",
        "L|1|N",
    ]
    return "\r".join(segments) + "\r"


def build_message(msg_type: str, specimen: str) -> str:
    """
    Build logical ASTM message depending on type:
    - RES   -> patient result, specimen is used in O-record
    - CHECK -> Background Check, always BACKGROUNDCHECK
    """
    msg_type = msg_type.upper()
    if msg_type == "RES":
        return get_sysmex_result_message(specimen)
    if msg_type == "CHECK":
        return get_sysmex_background_check_message()
    raise ValueError(f"Unsupported message type: {msg_type}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate a Sysmex analyzer sending a LAB-29 ASTM result to LabBook Connect."
    )
    parser.add_argument(
        "--host",
        required=True,
        help="LabBook Connect host (no default, mandatory).",
    )
    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="LabBook Connect port (no default, mandatory).",
    )
    parser.add_argument(
        "--type",
        choices=["RES", "CHECK"],
        required=True,
        help="Message type: RES = normal patient result, CHECK = BACKGROUNDCHECK QC",
    )
    parser.add_argument(
        "--specimen", "--sample-id",
        dest="specimen",
        help="Specimen ID for RES messages. Mandatory when --type RES. Ignored for CHECK.",
    )
    parser.add_argument(
        "--no-response",
        action="store_true",
        help="Do not wait for ASTM response from plugin.",
    )

    args = parser.parse_args()

    if args.type == "RES" and not args.specimen:
        raise SystemExit("ERROR: --specimen is mandatory when --type RES")

    astm_message = build_message(args.type, args.specimen)

    print("=== ASTM message to send (logical records) ===")
    print(astm_message.replace("\r", "\n"))

    addr = (args.host, args.port)
    print(f"\nConnecting to {addr[0]}:{addr[1]} as Sysmex client...")
    try:
        with socket.create_connection(addr, timeout=10.0) as sock:
            send_astm_message(sock, astm_message)
            if not args.no_response:
                response = receive_astm_from_plugin(sock)
            else:
                response = ""
    except Exception as e:
        print("ERROR during communication:", repr(e))
        return

    if not args.no_response and response:
        print("\n=== ASTM response from plugin ===")
        print(response.replace("\r", "\n"))
    elif not args.no_response:
        print("\nNo ASTM response received (empty or none).")


if __name__ == "__main__":
    main()
