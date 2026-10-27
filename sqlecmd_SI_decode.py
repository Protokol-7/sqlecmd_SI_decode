#!/usr/bin/env python3
"""
sqlecmd_SI_decode.py - decode the hex/BLOB "Value" data from SQLECmd's export of the
Windows Search index (Windows 11 Windows.db).

This works only from SQLECmd's CSV output, not from Windows.db directly. It never
opens a database itself.

Storage quirks handled (as seen in real Windows.db data, via SQLECmd's export):
  * many integers / floats are stored as ASCII text   (0x38323039 -> "8209")
  * dates are binary little-endian FILETIMEs          (0x00A819DD0584DA01)
  * strings are mostly UTF-8, some UTF-16LE           (0x433A5C... / 0x66006F00...)

Property names/types come from the SystemIndex_1_PropertyStore_Metadata CSV that
SQLECmd exports alongside PropertyStore.csv: automatic in folder mode, or pass
--meta <metadata CSV> in single-CSV mode. Without metadata the script decodes
heuristically.

All FILETIMEs are output in UTC.

Usage:
  python sqlecmd_SI_decode.py <SQLECmd output folder> [-o outdir] [--no-timeline]
      -> decodes every CSV in the folder (all original columns kept, a
         <column>_Decoded column added next to each hex column), uses the
         *_PropertyStore_Metadata CSV for types/names automatically, and builds
         a per-item timeline from the PropertyStore CSV
  python sqlecmd_SI_decode.py PropertyStore.csv -o decoded.csv [--meta meta.csv] [--pivot] [--props System.ItemPathDisplay ...]
"""
import argparse
import csv
import re
import struct
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# VARTYPE -> struct format
FIXED = {
    2: "<h", 3: "<i", 4: "<f", 5: "<d", 11: "<h", 16: "<b", 17: "<B", 18: "<H",
    19: "<I", 20: "<q", 21: "<Q", 22: "<i", 23: "<I", 64: "<Q",
}
STRING_TYPES = {8, 30, 31}  # BSTR, LPSTR, LPWSTR
VT_BOOL, VT_FILETIME, VT_CLSID, VT_VECTOR = 11, 64, 72, 0x1000
NUM_RE = re.compile(rb"-?\d+(\.\d+)?([eE][-+]?\d+)?")

PRIORITY = [
    "System.ItemPathDisplay", "System.ItemUrl", "System.ItemName", "System.FileName",
    "System.ItemType", "System.Size", "System.DateCreated", "System.DateModified",
    "System.DateAccessed", "System.FileOwner", "System.Search.GatherTime",
]


def norm(s):
    """'Work Id' / 'work_id' / 'WorkId' -> 'workid'"""
    return re.sub(r"[\s_]", "", s or "").lower()


# ---------------------------------------------------------------- primitives
def filetime_to_str(n):
    if not isinstance(n, int) or n <= 0:
        return None
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=n // 10)
    except OverflowError:
        return None
    if not 1980 <= dt.year <= 2100:
        return None
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def parse_hex(s):
    """'0x4100..' / '41-00-..' / '4100..' -> bytes, or None if not hex."""
    s = s.strip()
    if re.fullmatch(r"\d{1,7}", s):  # short plain number, not a blob
        return None
    if s.lower().startswith("0x"):
        s = s[2:]
        if not s:
            return b""
    s = re.sub(r"[\s\-:]", "", s)
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s)


def _looks_like_text(s, strict):
    t = s.replace("\x00", "")
    if not t:
        return False
    if sum(ch.isprintable() or ch in "\r\n\t" for ch in t) / len(t) < 0.9:
        return False
    return not strict or len(t) / len(s) >= 0.75  # text must fill the buffer


def _clean(s):
    return " | ".join(p for p in s.split("\x00") if p)  # NUL = multi-value separator


def decode_text(b, strict=False):
    if len(b) >= 2 and len(b) % 2 == 0 and b[1::2].count(0) >= len(b) // 4:
        try:
            s = b.decode("utf-16-le")
            if _looks_like_text(s, strict):
                return _clean(s)
        except UnicodeDecodeError:
            pass
    try:
        s = b.decode("utf-8")
        if _looks_like_text(s, strict):
            return _clean(s)
    except UnicodeDecodeError:
        pass
    return None


def ascii_number(b):
    return b.decode("ascii") if NUM_RE.fullmatch(b) else None


# ---------------------------------------------------------------- decoders
def heuristic(b):
    if not b:
        return ""
    t = decode_text(b, strict=True)
    if t is not None:
        return t
    n = len(b)
    if n == 8:
        v = struct.unpack("<Q", b)[0]
        return filetime_to_str(v) or str(v)
    if n == 4:
        return str(struct.unpack("<I", b)[0])
    if n == 2:
        return str(struct.unpack("<H", b)[0])
    if n == 1:
        return str(b[0])
    if n == 16:
        return str(uuid.UUID(bytes_le=b))
    return b.hex()


def _fmt_scalar(v, base):
    if base == VT_FILETIME:
        return filetime_to_str(v) or str(v)
    if base == VT_BOOL:
        return "True" if v else "False"
    return str(v)


def decode_typed(b, vt):
    if not b:
        return ""
    base, is_vec = vt & 0x0FFF, bool(vt & VT_VECTOR)
    if base in STRING_TYPES:
        t = decode_text(b)
        return t if t is not None else b.hex()
    if base == VT_CLSID and len(b) % 16 == 0:
        return " | ".join(str(uuid.UUID(bytes_le=b[i:i + 16])) for i in range(0, len(b), 16))
    if base in FIXED:
        num = ascii_number(b)  # numbers stored as text
        if num is not None:
            if base == VT_BOOL:
                return "True" if float(num) != 0 else "False"
            if base == VT_FILETIME and num.lstrip("-").isdigit():
                return filetime_to_str(int(num)) or num
            return num
        fmt = FIXED[base]
        size = struct.calcsize(fmt)
        if len(b) == size:
            vals = [struct.unpack(fmt, b)[0]]
        elif is_vec and len(b) % size == 0:
            vals = [struct.unpack_from(fmt, b, i)[0] for i in range(0, len(b), size)]
        elif len(b) < size and fmt[1] not in "fd":  # compacted integer
            vals = [int.from_bytes(b, "little", signed=fmt[1].islower())]
        else:
            return heuristic(b)
        return " | ".join(_fmt_scalar(v, base) for v in vals)
    return heuristic(b)


def decode_value(val, vt=None):
    if val is None:
        return ""
    if isinstance(val, (int, float)):
        if vt is not None and (vt & 0x0FFF) == VT_FILETIME:
            return filetime_to_str(int(val)) or str(val)
        return str(val)
    if isinstance(val, str):
        b = parse_hex(val)
        if b is None:
            return val
        val = b
    val = bytes(val)
    return decode_typed(val, vt) if vt is not None else heuristic(val)


# ---------------------------------------------------------------- metadata
def _meta_from_rows(cols, rows):
    nc = {norm(c): i for i, c in enumerate(cols)}
    id_i = nc.get("id")
    name_i = nc.get("name", nc.get("uniquekey"))
    type_i = nc.get("standardtype")
    if type_i is None:
        type_i = next((i for c, i in nc.items() if "type" in c), None)
    if id_i is None:
        return {}
    out = {}
    for r in rows:
        try:
            pid = int(r[id_i])
        except (TypeError, ValueError):
            continue
        try:
            vt = int(r[type_i]) if type_i is not None and r[type_i] not in (None, "") else None
        except (TypeError, ValueError):
            vt = None
        name = r[name_i] if name_i is not None and r[name_i] else f"Column_{pid}"
        out[pid] = (name, vt)
    print(f"[+] {len(out)} property definitions loaded "
          f"(type column: {cols[type_i] if type_i is not None else 'none'})", file=sys.stderr)
    return out


def load_meta(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        r = csv.reader(f)
        cols = next(r)
        return _meta_from_rows(cols, list(r))


# ---------------------------------------------------------------- output
def write_output(out, records, pivot):
    """records: iterable of (workid, colid, name, vt, decoded)"""
    n = 0
    with open(out, "w", newline="", encoding="utf-8-sig") as fo:
        w = csv.writer(fo)
        if not pivot:
            w.writerow(["WorkId", "ColumnId", "Property", "VarType", "Value"])
            for wid, cid, name, vt, val in records:
                w.writerow([wid, cid, name, "" if vt is None else vt, val])
                n += 1
        else:
            items, seen = {}, set()
            for wid, cid, name, vt, val in records:
                items.setdefault(wid, {})[name] = val
                seen.add(name)
            cols = [c for c in PRIORITY if c in seen] + sorted(seen - set(PRIORITY))
            w.writerow(["WorkId"] + cols)
            for wid, d in items.items():
                w.writerow([wid] + [d.get(c, "") for c in cols])
            n = len(items)
    print(f"[+] Wrote {n} rows to {out}", file=sys.stderr)


def run_csv(path, out, meta_path, pivot, props, metadata=None):
    csv.field_size_limit(2**31 - 1)
    if metadata is None:
        metadata = load_meta(meta_path) if meta_path else {}
    if not metadata:
        print("[!] No metadata - using heuristic decoding (pass --meta for real types/names)",
              file=sys.stderr)
    want = set(props) if props else None
    with open(path, newline="", encoding="utf-8-sig") as fi:
        r = csv.DictReader(fi)
        nc = {norm(c): c for c in r.fieldnames}
        vcol, ccol, wcol = nc.get("value"), nc.get("columnid"), nc.get("workid")
        if not vcol:
            sys.exit(f"[-] No 'Value' column. Columns: {r.fieldnames}")
        if pivot and not (ccol and wcol):
            sys.exit("[-] --pivot needs WorkId and ColumnId columns in the CSV")

        def records():
            for row in r:
                cid_raw = row.get(ccol, "") if ccol else ""
                try:
                    cid = int(cid_raw)
                except ValueError:
                    cid = cid_raw
                name, vt = metadata.get(cid, (f"Column_{cid}", None))
                if want and name not in want:
                    continue
                raw = row[vcol]
                yield (row.get(wcol, "") if wcol else ""), cid, name, vt, \
                    (decode_value(raw, vt) if raw else "")

        write_output(out, records(), pivot)


# ---------------------------------------------------------------- folder mode
HEX_CELL = re.compile(r"0x[0-9A-Fa-f]*")


def detect_hex_cols(path, sample=5000):
    """Columns where most non-empty sampled cells look like 0x... hex."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        r = csv.DictReader(f)
        cols = r.fieldnames or []
        hits, filled = dict.fromkeys(cols, 0), dict.fromkeys(cols, 0)
        for i, row in enumerate(r):
            if i >= sample:
                break
            for c in cols:
                v = (row.get(c) or "").strip()
                if v:
                    filled[c] += 1
                    hits[c] += bool(HEX_CELL.fullmatch(v))
    return cols, [c for c in cols if filled[c] and hits[c] / filled[c] >= 0.5]


def decode_csv_file(path, out, metadata):
    """Copy a CSV, adding <col>_Decoded next to every hex column."""
    cols, hexcols = detect_hex_cols(path)
    name = Path(path).name
    if not hexcols:
        print(f"[=] {name}: no hex columns, nothing to decode", file=sys.stderr)
        return
    nc = {norm(c): c for c in cols}
    ccol = nc.get("columnid")
    tcol = nc.get("standardtype") or next((c for k, c in nc.items() if "type" in k), None)
    add_prop = bool(metadata and ccol and not ({"name", "uniquekey"} & nc.keys()))

    out_cols = []
    for c in cols:
        if add_prop and c == ccol:
            out_cols += [c, "Property"]
        else:
            out_cols.append(c)
        if c in hexcols:
            out_cols.append(f"{c}_Decoded")

    n = 0
    with open(path, newline="", encoding="utf-8-sig") as fi, \
         open(out, "w", newline="", encoding="utf-8-sig") as fo:
        r = csv.DictReader(fi)
        w = csv.DictWriter(fo, fieldnames=out_cols, extrasaction="ignore")
        w.writeheader()
        for row in r:
            vt, prop = None, ""
            if tcol:  # per-row type (e.g. joined file)
                try:
                    vt = int(row.get(tcol) or "")
                except ValueError:
                    pass
            if ccol and metadata:
                try:
                    prop, mvt = metadata.get(int(row.get(ccol) or ""), ("", None))
                except ValueError:
                    mvt = None
                if vt is None:
                    vt = mvt
            if add_prop:
                row["Property"] = prop
            for c in hexcols:
                raw = row.get(c) or ""
                # the property type only applies to the Value column
                row[f"{c}_Decoded"] = decode_value(raw, vt if norm(c) == "value" else None) if raw else ""
            w.writerow(row)
            n += 1
    print(f"[+] {name}: decoded {', '.join(hexcols)} -> {Path(out).name} ({n} rows)", file=sys.stderr)


def run_dir(folder, outdir, timeline=True):
    csv.field_size_limit(2**31 - 1)
    folder = Path(folder)
    outdir = Path(outdir) if outdir else folder / "decoded"
    outdir.mkdir(parents=True, exist_ok=True)
    files = sorted(folder.glob("*.csv"))
    if not files:
        sys.exit(f"[-] No CSV files in {folder}")

    metafile = next((p for p in files
                     if re.search(r"SystemIndex_\d+_PropertyStore_Metadata", p.name)), None)
    metadata = load_meta(str(metafile)) if metafile else {}
    if not metadata:
        print("[!] No *_PropertyStore_Metadata CSV found - heuristic decoding only", file=sys.stderr)

    for p in files:
        decode_csv_file(p, outdir / f"{p.stem}_decoded.csv", metadata)
        if timeline and re.search(r"SystemIndex_\d+_PropertyStore_[0-9a-fA-F]{8}-", p.name):
            print(f"[*] Building per-item timeline from {p.name} ...", file=sys.stderr)
            run_csv(str(p), str(outdir / f"{p.stem}_timeline.csv"), None, True, None, metadata)
    print(f"[+] Done. Output in {outdir}", file=sys.stderr)


def reject_if_sqlite(path):
    try:
        with open(path, "rb") as f:
            is_db = f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return
    if is_db:
        sys.exit(
            f"[-] {path} is a SQLite database. This script only decodes SQLECmd's CSV "
            "output, not Windows.db directly. Run SQLECmd against the database first, "
            "then point this script at its output folder (or a single CSV)."
        )


def main():
    ap = argparse.ArgumentParser(
        description="Decode Value blobs in SQLECmd's export of the Windows Search index")
    ap.add_argument("input", help="SQLECmd output folder, or a single CSV from it")
    ap.add_argument("-o", "--output", help="output CSV (file modes) or output folder (folder mode, "
                                           "default: <input>/decoded)")
    ap.add_argument("--no-timeline", action="store_true", help="folder mode: skip the per-item timeline")
    ap.add_argument("--pivot", action="store_true", help="one row per WorkId (indexed item)")
    ap.add_argument("--props", nargs="+", help="only these properties, e.g. System.ItemPathDisplay")
    ap.add_argument("--meta", help="single-CSV mode: a CSV export of the _Metadata table")
    a = ap.parse_args()

    if Path(a.input).is_dir():
        run_dir(a.input, a.output, not a.no_timeline)
        return
    reject_if_sqlite(a.input)
    if not a.output:
        ap.error("-o/--output is required for a single file")
    run_csv(a.input, a.output, a.meta, a.pivot, a.props)


if __name__ == "__main__":
    main()
