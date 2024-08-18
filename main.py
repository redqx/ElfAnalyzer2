from ElfAnalyzer import *

file = open("test/elfloader", "rb")

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
        Relocation_Tables_organize,
        load_list_byprogram,
        load_list_dtag
)=parse_elffile(file)

#查找函数
[idx,sym]=mm_dlsym("worker", symbol_list['.dynamic']['list'], hash_table, gnu_hash_table,elf_class)


file.close()