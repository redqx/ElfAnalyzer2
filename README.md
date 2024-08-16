# ElfAnalyzer

## Description

This module parses and analyzes ELF file for Forensic and investigations.

Parses:
 - ELF identification
 - ELF headers
 - Program headers
 - ELF sections
 - ELF symbols tables
 - Comment section
 - Note sections
 - Dynamic section

## Requirements

This package require:
 - python3
 - python3 Standard Library

### Optional

 - matplotlib
 - EntropyAnalysis

> *Matplotlib* and *EntropyAnalysis* are not installed by *ProgramExecutableAnalyzer* because this package can be installed on server without GUI.
> You can install optinal required packages with the following command: `python3 -m pip install matplotlib EntropyAnalysis`

## Installation

```bash
python3 -m pip install ElfAnalyzer
```

```bash
git clone "https://github.com/mauricelambert/ElfAnalyzer.git"
cd "ElfAnalyzer"
python3 -m pip install .
```

## Usages



### Python script

```python
from ElfAnalyzer import *

file = open("./local/ElfFile", "rb")
elfindent, elf_headers, programs_headers, elf_sections, symbols_tables, comments, note_sections, notes, dynamics, sections = parse_elffile(file)
cli(elfindent, elf_headers, programs_headers, elf_sections, symbols_tables, comments, notes, dynamics, sections)
file.close()
```

## Links

 - [Pypi](https://pypi.org/project/ElfAnalyzer)
 - [Github](https://github.com/user/ElfAnalyzer)
 - [Documentation](https://mauricelambert.github.io/info/python/security/ElfAnalyzer.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/ElfAnalyzer.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/ElfAnalyzer.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
