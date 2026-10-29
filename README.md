# sqlecmd_SI_decode

Decodes the hex/BLOB `Value` column in SQLECmd's CSV export of the Windows Search index (`Windows.db`, Windows 11).

Works only from SQLECmd's CSV output, not from `Windows.db` directly. It never opens a database itself.

## What it handles

Storage quirks seen in real `Windows.db` data, via SQLECmd's export:

- integers and floats stored as ASCII text (`0x38323039` -> `8209`)
- dates as binary little-endian FILETIMEs (`0x00A819DD0584DA01`)
- strings mostly UTF-8, some UTF-16LE (`0x433A5C...` / `0x66006F00...`)

Property names and types come from the `SystemIndex_1_PropertyStore_Metadata` CSV that SQLECmd exports alongside `PropertyStore.csv`: automatic in folder mode, or pass `--meta <metadata CSV>` in single-CSV mode. Without metadata it decodes heuristically.

All FILETIMEs are output in UTC.

## Usage

```
python sqlecmd_SI_decode.py <SQLECmd output folder> [-o outdir] [--no-timeline]
```

Decodes every CSV in the folder. Keeps all original columns, adds a `<column>_Decoded` column next to each hex column, uses the `*_PropertyStore_Metadata` CSV for types/names automatically, and builds a per-item timeline from the PropertyStore CSV.

```
python sqlecmd_SI_decode.py PropertyStore.csv -o decoded.csv [--meta meta.csv] [--pivot] [--props System.ItemPathDisplay ...]
```

Single-CSV mode. `--pivot` gives one row per WorkId (indexed item) instead of one row per property. `--props` filters to specific properties.

## Requirements

Python 3, standard library only.

## License

MIT, see [LICENSE](LICENSE).
