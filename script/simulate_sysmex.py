#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sysmex instrument simulator for the LabBook Connect plugin.

The plugin listens (analyzer_sysmex.toml, [analyzer.socket] mode = "server"), so this script
connects to it the way an XN or XP analyzer does.

It speaks ASTM E1381 as described in the Sysmex communication specifications:

  Establishment  ENQ -> ACK
  Transfer       <STX> F# Text <ETB|ETX> C1 C2 <CR> <LF>
  Termination    EOT

Frames carry at most 240 characters of message text. Every record inside the text is terminated
by CR. All frames but the last end with ETB, the last one with ETX.

Usage:
    python3 simulate_sysmex.py --host 127.0.0.1 --port 7500 --scenario results --specimen 1535
    python3 simulate_sysmex.py --scenario query --specimen 1535
    python3 simulate_sysmex.py --scenario qc
    python3 simulate_sysmex.py --scenario results --nak-frame 1
"""

import argparse
import socket
import sys
import time

ENQ = 0x05
ACK = 0x06
NAK = 0x15
EOT = 0x04
STX = 0x02
ETX = 0x03
ETB = 0x17
CR = 0x0D
LF = 0x0A

NAMES = {ENQ: "ENQ", ACK: "ACK", NAK: "NAK", EOT: "EOT", STX: "STX"}

MAX_FRAME_TEXT = 240
REPLY_TIMEOUT = 15
RECEIVE_TIMEOUT = 30

# The analytes of mapping_sysmex.toml, with values taken from a real XN-350 trace.
# The list follows the mapping file, not the LIS referential: what does not show up in the
# record then tells which lis_result_code does not match a code_var on that installation.
# Entries are (code, value, unit, abnormal flag). The last four are alarms, which the analyzer
# emits without a value.
ANALYTES = [
    ("RBC", "7.51", "10*6/uL", "N"),
    ("HGB", "19.3", "g/dL", "N"),
    ("HCT", "65.1", "%", "N"),
    ("MCV", "86.7", "fL", "N"),
    ("MCH", "25.7", "pg", "N"),
    ("MCHC", "29.6", "g/dL", "N"),
    ("WBC", "13.73", "10*3/uL", "N"),
    ("PLT", "161", "10*3/uL", "N"),
    ("NEUT#", "2.46", "10*3/uL", "N"),
    ("NEUT%", "17.9", "%", "N"),
    ("LYMPH#", "10.58", "10*3/uL", "N"),
    ("LYMPH%", "77.1", "%", "N"),
    ("MONO#", "0.65", "10*3/uL", "N"),
    ("MONO%", "4.7", "%", "N"),
    ("EO#", "0.01", "10*3/uL", "N"),
    ("EO%", "0.1", "%", "N"),
    ("BASO#", "0.03", "10*3/uL", "N"),
    ("BASO%", "0.2", "%", "N"),
    ("IG#", "0.04", "10*3/uL", "N"),
    ("IG%", "0.3", "%", "N"),
    ("RDW-CV", "14.3", "%", "N"),
    ("RDW-SD", "45.9", "fL", "N"),
    ("MICROR", "0.9", "%", "N"),
    ("MACROR", "15.7", "%", "N"),
    ("MPV", "8.8", "fL", "N"),
    ("PDW", "8.9", "fL", "N"),
    ("P-LCR", "16.4", "%", "N"),
    ("PCT", "0.14", "%", "N"),
    ("RET#", "0.0601", "10*6/uL", "N"),
    ("RET%", "0.80", "%", "N"),
    ("IRF", "3.4", "%", "N"),
    ("RET-HE", "18.5", "pg", "N"),
    ("RBC-HE", "18.4", "pg", "N"),
    ("DELTA-HE", "0.1", "pg", "N"),
    ("HYPO-HE", "3.5", "%", "N"),
    ("HYPER-HE", "0.3", "%", "N"),
    ("Neutrophilia", "", "", "A"),
    ("Lymphopenia", "", "", "A"),
    ("PLT_Clumps?", "", "", "A"),
    ("Blasts/Abn_Lympho?", "", "", "A"),
]


def now():
    return time.strftime("%Y%m%d%H%M%S")


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------

def header():
    """H record as an XN-350 emits it."""
    return "H|\\^&|||    XN-350^00-27^15735^^^^AW618382||||||||E1394-97"


def build_message(scenario, specimen):
    if scenario == "results":
        # Analyzer to host. The specimen sits in field 9.4.4, attribute M for a manual entry.
        records = [header(),
                   "P|1||||^^|||U|||||^||||||||||||^^^",
                   "C|1||",
                   "O|1||^^" + specimen + "^M|" +
                   "\\".join("^^^^" + a[0] for a in ANALYTES) +
                   "|||||||N||||||||||||||F",
                   "C|1||"]

        for index, (code, value, unit, flag) in enumerate(ANALYTES, start=1):
            records.append("R|%d|^^^^%s^1|%s|%s||%s||F||||%s"
                           % (index, code, value, unit, flag, now()))

        records.append("C|1||")
        records.append("L|1|N")
        return records

    if scenario == "qc":
        # Quality control run. The plugin archives these messages but does not forward them.
        records = [header(),
                   "P|1||||^^|||U|||||^||||||||||||^^^",
                   "O|1||^^BACKGROUNDCHECK^M|^^^^WBC\\^^^^RBC|||||||Q||||||||||||||F"]

        for index, (code, value, unit, flag) in enumerate(ANALYTES[:2], start=1):
            records.append("R|%d|^^^^%s^1|%s|%s||%s||F||||%s"
                           % (index, code, value, unit, flag, now()))

        records.append("L|1|N")
        return records

    if scenario == "query":
        # Order request. Rack and position are left empty, only the sample number is given.
        return [header(),
                "Q|1|^^" + specimen + "^B||||" + now(),
                "L|1|N"]

    raise SystemExit("unknown scenario: " + scenario)


# --------------------------------------------------------------------------
# Framing
# --------------------------------------------------------------------------

def checksum(frame_no, text, terminator):
    total = ord(str(frame_no))
    for ch in text.encode("ascii", "replace"):
        total += ch
    total += terminator
    return "%02X" % (total & 0xFF)


def split_frames(records):
    text = "".join(r + "\r" for r in records)
    return [text[i:i + MAX_FRAME_TEXT] for i in range(0, len(text), MAX_FRAME_TEXT)] or [""]


def encode_frame(frame_no, chunk, last):
    terminator = ETX if last else ETB
    out = bytearray([STX])
    out.extend(str(frame_no).encode("ascii"))
    out.extend(chunk.encode("ascii", "replace"))
    out.append(terminator)
    out.extend(checksum(frame_no, chunk, terminator).encode("ascii"))
    out.append(CR)
    out.append(LF)
    return bytes(out)


# --------------------------------------------------------------------------
# Link
# --------------------------------------------------------------------------

class Link:
    def __init__(self, sock, verbose):
        self.sock = sock
        self.verbose = verbose

    def send_byte(self, value):
        print("  >>> %s" % NAMES.get(value, hex(value)))
        self.sock.sendall(bytes([value]))

    def read_byte(self, timeout):
        self.sock.settimeout(timeout)
        data = self.sock.recv(1)
        if not data:
            raise ConnectionError("connection closed by the plugin")
        value = data[0]
        print("  <<< %s" % NAMES.get(value, repr(chr(value))))
        return value

    def send_message(self, records):
        print("\n[TRANSFER] sending %d record(s)" % len(records))
        for r in records:
            print("    %s" % (r[:110] + ("..." if len(r) > 110 else "")))

        self.send_byte(ENQ)
        if self.read_byte(REPLY_TIMEOUT) != ACK:
            print("  [FAIL] expected ACK after ENQ")
            return False

        chunks = split_frames(records)
        print("  [INFO] %d frame(s) of at most %d characters" % (len(chunks), MAX_FRAME_TEXT))

        frame_no = 1
        for index, chunk in enumerate(chunks):
            last = (index == len(chunks) - 1)
            print("  >>> frame %d (%d characters, %s)"
                  % (frame_no, len(chunk), "ETX" if last else "ETB"))
            if self.verbose:
                print("      %r" % chunk)
            self.sock.sendall(encode_frame(frame_no, chunk, last))

            if self.read_byte(REPLY_TIMEOUT) != ACK:
                print("  [FAIL] frame %d was not accepted" % frame_no)
                self.send_byte(EOT)
                return False
            frame_no = (frame_no + 1) % 8

        self.send_byte(EOT)
        return True

    def receive_message(self, nak_frame=None):
        print("\n[RECEIVE] waiting for the plugin")
        try:
            first = self.read_byte(RECEIVE_TIMEOUT)
        except socket.timeout:
            print("  [INFO] nothing received within %d s" % RECEIVE_TIMEOUT)
            return None

        if first != ENQ:
            print("  [FAIL] expected ENQ, got %s" % hex(first))
            return None

        self.send_byte(ACK)

        text = ""
        expected = 1
        naked = set()

        while True:
            byte = self.read_byte(RECEIVE_TIMEOUT)

            if byte == EOT:
                print("  [INFO] transfer finished")
                break

            if byte != STX:
                print("  [WARN] expected STX, got %s, ignored" % hex(byte))
                continue

            frame_no = int(chr(self.sock.recv(1)[0]))

            payload = bytearray()
            while True:
                b = self.sock.recv(1)[0]
                if b in (ETX, ETB):
                    terminator = b
                    break
                payload.append(b)

            raw_checksum = self.sock.recv(2).decode("ascii", "replace")
            self.sock.recv(2)

            body = payload.decode("ascii", "replace")
            wanted = checksum(frame_no, body, terminator)
            ok = (wanted.upper() == raw_checksum.upper())

            print("  <<< frame %d (%d characters, %s, checksum %s %s)"
                  % (frame_no, len(body), "ETX" if terminator == ETX else "ETB",
                     raw_checksum, "ok" if ok else "expected " + wanted))
            if self.verbose:
                print("      %r" % body)

            if frame_no != expected:
                print("  [WARN] frame number %d received, %d expected" % (frame_no, expected))

            if nak_frame is not None and frame_no == nak_frame and frame_no not in naked:
                naked.add(frame_no)
                print("  [TEST] rejecting frame %d once" % frame_no)
                self.send_byte(NAK)
                continue

            if not ok:
                self.send_byte(NAK)
                continue

            text += body
            self.send_byte(ACK)
            expected = (frame_no + 1) % 8

        return text


# --------------------------------------------------------------------------

def report(text, scenario):
    if not text:
        print("\n[RESULT] the plugin sent nothing")
        if scenario == "qc":
            print("[CHECK] expected, a quality control run is archived but not forwarded")
        return

    records = [r for r in text.replace("\r\n", "\r").split("\r") if r]
    print("\n[RESULT] %d record(s) received" % len(records))
    for r in records:
        print("    %s" % (r[:110] + ("..." if len(r) > 110 else "")))

    for line in records:
        if line.startswith("L|"):
            fields = line.split("|")
            code = fields[2] if len(fields) > 2 else ""
            if scenario == "results":
                print("[CHECK] L-3 = %s, %s"
                      % (code, "results accepted" if code == "Y" else "results refused"))
            else:
                print("[CHECK] L-3 = %s, the specification only defines N" % code)

        if line.startswith("O|"):
            fields = line.split("|")
            print("[CHECK] order record, specimen in field 3 = %r, field 4 = %r"
                  % (fields[2] if len(fields) > 2 else "",
                     fields[3] if len(fields) > 3 else ""))

    if scenario == "qc" and records:
        print("[CHECK] the plugin answered a quality control run, it should stay silent")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7500)
    parser.add_argument("--scenario", default="results",
                        choices=["results", "qc", "query"])
    parser.add_argument("--specimen", default="1535")
    parser.add_argument("--nak-frame", type=int, default=None,
                        help="reject this frame once when receiving, to check retransmission")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    records = build_message(args.scenario, args.specimen)

    print("[INFO] connecting to %s:%d" % (args.host, args.port))
    with socket.create_connection((args.host, args.port), timeout=REPLY_TIMEOUT) as sock:
        link = Link(sock, args.verbose)

        if not link.send_message(records):
            return 1

        text = link.receive_message(nak_frame=args.nak_frame)
        report(text, args.scenario)

    return 0


if __name__ == "__main__":
    sys.exit(main())
