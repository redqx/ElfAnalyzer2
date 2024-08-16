programs_headers_organize

list 数组类型

```python

    organize_program = {}
    organize_program["PT_PHDR"] = []# List[Union[ProgramHeader32, ProgramHeader64]] 
    organize_program["PT_INTERP"] = [] 
    organize_program["PT_LOAD"] = [] 
    organize_program["PT_DYNAMIC"] = []
    organize_program["PT_NOTE"] = []
    organize_program['PT_GNU_PROPERTY'] = []
    organize_program["PT_GNU_EH_FRAME"] = []
    organize_program["PT_GNU_STACK"] = []
    organize_program["PT_GNU_RELRO"] = []

    organize_sections={}
    # 声明一下
    organize_sections['SHT_PROGBITS']={}
    organize_sections['SHT_NOTE']={}
    organize_sections['SHT_GNU_HASH']={}
    organize_sections['SHT_DYNSYM']={}
    organize_sections['SHT_STRTAB']={}
    organize_sections['SHT_GNU_versym']={}
    organize_sections['SHT_GNU_verdneed']={}
    organize_sections['SHT_RELA']={}
    organize_sections['SHT_INIT_ARRAY']={}
    organize_sections['SHT_FINI_ARRAY']={}
    organize_sections['SHT_DYNAMIC']={}
    organize_sections['SHT_NOBITS']={}
    organize_sections['SHT_SYMTAB']={}

```