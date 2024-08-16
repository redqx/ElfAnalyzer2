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





## Usages



### Python script

```python
from ElfAnalyzer import *

file = open("test/hello.so.nosec", "rb")

# 信息获取
(
        elf_indent,
        elf_class,
        elf_headers,
        programs_headers,
        programs_headers_organize,
        dyn_items,
        dyn_items_organize,
        hash_table,
        gnu_hash_table,
        dynsym_cnt,
        symbol_items,
        symbol_list,
        Relocation_Tables,
        Relocation_Tables_organize
)=parse_elffile(file)

#查找函数
[idx,sym]=mm_dlsym("worker", symbol_list['.dynamic']['list'], hash_table, gnu_hash_table,elf_class)


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
