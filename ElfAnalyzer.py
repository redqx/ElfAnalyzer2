#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''

The original project: https://github.com/mauricelambert/ElfAnalyzer
the upgraded project: https://github.com/mauricelambert/ElfAnalyzer

'''
from ctypes import c_char_p
from typing import TypeVar,Iterable, List, Tuple, Dict
from _io import _BufferedIOBase
from string import printable

# ----------------------------------
from mm_type.utils import update_dict
from mm_type import *
from mm_type.mm_ctype import DataToCClass
from mm_type.mm_elftype import *



try:
    from EntropyAnalysis import charts_chunks_file_entropy, Section
    from matplotlib import pyplot
except ImportError:
    entropy_charts_import = False
else:
    entropy_charts_import = True

_CData = tuple(x for x in c_char.mro() if x.__name__ == "_CData")[0]
Section = TypeVar("Section")
printable = printable[:-5].encode()
Structure = TypeVar("Structure")


def enum_from_value(value: _CData, enum_class: Enum, info: str = "") -> Field:
    """
    This function returns a Field with Enum name and value.
    """

    for constant in enum_class:
        if constant.value == value.value:
            return Field(
                value,
                constant.name + info,  #自定义添加,弃用usage和description
                getattr(constant.value, "usage", None),
                getattr(constant.value, "description", None),
            )
    return Field(value, "UN_DEFINED")


def enum_from_flags(value: _CData, enum_class: Enum, info: str = "") -> Iterable[Field]:
    """
    This function yields Fields with Enum name and value.
    """
    for constant in enum_class:
        if constant.value & value.value:
            yield Field(
                value,
                constant.name + info,
                getattr(constant.value, "usage", None),
                getattr(constant.value, "description", None),
            )
        # 如何返回的,不是很清楚


def read_file_from_struct(file: _BufferedIOBase, structure: type) -> Structure:
    """
    This function reads file and parse readed data
    to Structure and returns it.
    """

    return structure(file.read(sizeof(structure)))


def read_until(file: _BufferedIOBase, end_data: bytes) -> bytes:
    """
    This function reads file until data end doesn't match the end_data params.
    """

    old_position = file.tell()
    data = file.read(1)
    position = file.tell()
    while not data.endswith(end_data) and old_position < position:
        old_position = position
        data += file.read(1)
        position = file.tell()

    return data


def read_string_fromfile(file: _BufferedIOBase) -> c_char_p:
    """
    This function reads file a NULL terminating string from file position.
    """

    return c_char_p(read_until(file, b"\0"))


def get_padding_length(data_size: int, padding_to: int) -> int:
    """
    This function returns the padding length for this field.
    """

    padding_length = data_size % padding_to
    return padding_to - padding_length if padding_length else 0




def parse_dynamic_HASH(
        file: _BufferedIOBase,
        dyn_items_organize: Dict[str, Union[Dynamic32, Dynamic64]]
) -> Tuple[HashTable, Any]:
    if 'DT_HASH' not in dyn_items_organize.keys():
        return (None, 0)
    dyn_hash = dyn_items_organize['DT_HASH']
    file.seek(dyn_hash.d_value.value)
    mm_HashTable = read_file_from_struct(file, HashTable)
    mm_HashTable.buckets = []
    for i in range(mm_HashTable.nbucket.value):
        bucket = read_file_from_struct(file, mm_Elf32_Word)
        mm_HashTable.buckets.append(bucket.item)
    mm_HashTable.chains = []
    for i in range(mm_HashTable.nchain.value):
        chain = read_file_from_struct(file, mm_Elf32_Word)
        mm_HashTable.chains.append(chain.item)
    return (
        mm_HashTable,
        mm_HashTable.nchain.value
    )


def parse_dynamic_GNU_HASH(
        file: _BufferedIOBase,
        dyn_items_organize: Dict[str, Union[Dynamic32, Dynamic64]],
        elf_classe: str,
) -> Tuple[GnuHashTable, Any]:
    dict_keys = dyn_items_organize.keys()
    if 'DT_GNU_HASH' not in dict_keys:
        return (None, 0)

    mm_gnu_hash = dyn_items_organize['DT_GNU_HASH']

    file.seek(mm_gnu_hash.d_value.value)
    mm_GnuHashTable: GnuHashTable = read_file_from_struct(file, GnuHashTable)
    mm_GnuHashTable.blooms = []

    bloom_type = mm_Elf32_Word

    if elf_classe == '64':
        bloom_type = mm_Elf64_Xword
    for i in range(mm_GnuHashTable.bloomSize.value):
        bloom = read_file_from_struct(file, bloom_type)
        mm_GnuHashTable.blooms.append(bloom.item)

    mm_GnuHashTable.buckets = []
    sym_table_idx_max = 0
    for i in range(mm_GnuHashTable.nbucket.value):
        bucket = read_file_from_struct(file, mm_Elf32_Word)
        mm_GnuHashTable.buckets.append(bucket.item)
        if sym_table_idx_max < bucket.item.value:
            sym_table_idx_max = bucket.item.value

    if sym_table_idx_max < mm_GnuHashTable.symndx.value:  #可以寻到的最大值都小于symdnx, 那就没意思了
        sym_table_cnt = mm_GnuHashTable.symndx.value #数量
    else:
        sym_table_cnt = sym_table_idx_max + 1 #符号的数量


    # sym_table_cnt是符号的数量,不是chains的数量
    # sym_table_cnt = len(sym_table) = len(chains) + symndx

    nchain = sym_table_cnt - mm_GnuHashTable.symndx.value
    mm_GnuHashTable.chains = []
    for i in range(nchain):
        chani = read_file_from_struct(file, mm_Elf32_Word)
        mm_GnuHashTable.chains.append(chani.item)
        #print(chani.value & 1)

    # 此刻大概是读取到末尾了,但不一定是末尾
    # 尝试再读取
    while mm_GnuHashTable.chains[-1].value & 1 == 0:
        chani = read_file_from_struct(file, mm_Elf32_Word)
        mm_GnuHashTable.chains.append(chani.item)
        sym_table_cnt += 1

    return (
        mm_GnuHashTable,
        sym_table_cnt
    )


def parse_elfheader_ident(file: _BufferedIOBase) -> Tuple[ElfIdent, str]:
    """
    This function parses ELF identification headers. 会确定数据的读取的端序
    :param file: ELF file
    :return: 1),返回elf header中Ident[16]的信息, 2), 返回文件用什么寻址
    """

    elf_ident = read_file_from_struct(file, ElfIdent)  #从elf读取数据,读取的长度取决于传递进去的结构体大小, 传递进去的是一个class,该class类似于结构体的形式
    elf_ident.ei_mag = Field(
        elf_ident.ei_mag,
        "Magic number and other info"
        if elf_ident.ei_mag.value == b"\x7fELF"
        else "Invalid magic bytes",
    )

    elf_ident.ei_class = enum_from_value(elf_ident.ei_class, ELfIdentClass, " :address mode,x86 or x64 [寻址模式]")
    elf_classe = "64" if elf_ident.ei_class.value.value == 2 else "32"  #寻址模式
    elf_ident.ei_data = enum_from_value(elf_ident.ei_data, ELfIdentData, " :endian, LSB:little,MSB:big [端序]")  #大小端序

    DataToCClass.order = (
        "little" if elf_ident.ei_data.value.value == 1 else "big"
    )
    elf_ident.ei_version = enum_from_value(
        elf_ident.ei_version, ELfIdentVersion, " :elf-file format version [elf文件格式的版本?]"  #文件版本
    )
    elf_ident.ei_osabi = enum_from_value(elf_ident.ei_osabi, ELfIdentOS,
                                         " :should run in xxx OSABI system [应该运行在类系统上]")  #应该运行在什么系统上

    elf_ident.ei_abiversion = Field(
        elf_ident.ei_abiversion,
        "OS specified" if elf_ident.ei_abiversion else "OS unspecified",
    )

    elf_ident.ei_pad = Field(elf_ident.ei_pad, "Start padding")
    elf_ident.ei_nident = Field(elf_ident.ei_nident, "Padding")

    return elf_ident, elf_classe


def parse_elfheader(file: _BufferedIOBase, elf_classe: str) -> Union[ElfHeader32, ElfHeader64]:
    """
    This function parses ELF headers. 返回elf header相关信息
    """

    file.seek(0)

    elf_header = read_file_from_struct(
        file, globals()["ElfHeader" + elf_classe]
    )

    elf_header.e_type = enum_from_value(elf_header.e_type, ElfType, " :elf-file mm_type, DYN,REL,EXEC... [elf文件类型]")
    elf_header.e_machine = enum_from_value(elf_header.e_machine, ElfMachine)
    elf_header.e_version = enum_from_value(elf_header.e_version, ELfIdentVersion," : same to elf_ident.ei_version, value must be '1'")

    elf_header.e_entry = Field(
        elf_header.e_entry,
        "Entry point" if elf_header.e_entry else "No entry point",
    )

    elf_header.e_phoff = Field(
        elf_header.e_phoff,
        "Program header table offset"
        if elf_header.e_phoff
        else "No program header table",
    )

    elf_header.e_shoff = Field(
        elf_header.e_shoff,
        "Section table offset" if elf_header.e_shoff else "No header table",
    )

    elf_header.e_flags = Field(elf_header.e_flags, "Processor specific flags")
    elf_header.e_ehsize = Field(elf_header.e_ehsize, "ELF header's size")

    elf_header.e_phentsize = Field(
        elf_header.e_phentsize, "Entry header table size; sizeof(struct ProgramHeader)"
    )

    elf_header.e_phnum = Field(elf_header.e_phnum, "Header table entry number; count ProgramHeader")

    elf_header.e_shentsize = Field(
        elf_header.e_shentsize, "Entry section header's size; sizeof(struct SectionHeader)"
    )

    elf_header.e_shnum = Field(
        elf_header.e_shnum, "Section header entry number; count SectionHeader"
    )

    elf_header.e_shstrndx = Field(
        elf_header.e_shstrndx, "Section header table address"
    )

    return elf_header


# 数据写好, 工具直接拿去用(无脑那种), 而不是去提取.
def parse_program_headers(  # v1.1
        file: _BufferedIOBase,
        elf_header: Union[ElfHeader32, ElfHeader64],
        elf_classe: str,
) -> Tuple[
    List[Union[ProgramHeader32, ProgramHeader64]],
    Dict[str, List[Union[ProgramHeader32, ProgramHeader64]]]
]:
    file.seek(elf_header.e_phoff.value.value)  #移动指针到program header table

    elf_programs = [
        read_file_from_struct(file, globals()["ProgramHeader" + elf_classe])
        for _ in range(elf_header.e_phnum.value.value)
    ]  # 获取所有section 表

    organize_program = {}
    organize_program["PT_PHDR"] = []
    organize_program["PT_INTERP"] = []
    organize_program["PT_LOAD"] = []  #声明
    organize_program["PT_DYNAMIC"] = []
    organize_program["PT_NOTE"] = []
    organize_program['PT_GNU_PROPERTY'] = []
    organize_program["PT_GNU_EH_FRAME"] = []
    organize_program["PT_GNU_STACK"] = []
    organize_program["PT_GNU_RELRO"] = []

    for elf_table in elf_programs:
        elf_table.p_type = enum_from_value(elf_table.p_type, ProgramHeaderType)  # 禁止添加info,不然后面会出错
        elf_table.flags = [
            *enum_from_flags(elf_table.p_flags, ProgramHeaderFlags)
        ]

        elf_table.p_offset = Field(
            elf_table.p_offset, "Program header file position [段的文件偏移]"
        )

        elf_table.p_vaddr = Field(
            elf_table.p_vaddr, "Program header virtual position [段内存偏移]"
        )

        elf_table.p_paddr = Field(
            elf_table.p_paddr, "Program header physical position [不知道啥意思]"
        )

        elf_table.p_filesz = Field(
            elf_table.p_filesz, "Segment size in bytes in file image [段在文件中的大小]"
        )

        elf_table.p_memsz = Field(
            elf_table.p_memsz, "Segment size in bytes in memory image [段在内存中的大小]"
        )

        elf_table.p_align = Field(
            elf_table.p_align,
            "No segment alignment"
            if elf_table.p_align.value in (0, 1)
            else "Segment alignment [对齐粒度]",
        )

        if elf_table.p_type.value.value == ProgramHeaderType.PT_PHDR.value:
            organize_program["PT_PHDR"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_INTERP.value:
            organize_program["PT_INTERP"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_LOAD.value:
            organize_program["PT_LOAD"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_DYNAMIC.value:
            organize_program["PT_DYNAMIC"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_NOTE.value:
            organize_program["PT_NOTE"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_GNU_PROPERTY.value:
            organize_program["PT_GNU_PROPERTY"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_GNU_EH_FRAME.value:
            organize_program["PT_GNU_EH_FRAME"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_GNU_STACK.value:
            organize_program["PT_GNU_STACK"].append(elf_table)
        elif elf_table.p_type.value.value == ProgramHeaderType.PT_GNU_RELRO.value:
            organize_program["PT_GNU_RELRO"].append(elf_table)

    return (
        elf_programs,
        organize_program
    )


def parse_sections_headers(
        file: _BufferedIOBase,
        elf_header: Union[ElfHeader32, ElfHeader64],
        elf_classe: str,
) -> Tuple[
    List[Union[SectionHeader32, SectionHeader64]],
    Dict[str, Dict[str, Union[SectionHeader32, SectionHeader64]]]
]:
    """
    This function parses ELK sections.
    """
    # if elf_header.e_shoff.value.value == 0:
    #     return [], None, None, None, None, None, None, [], []
    if elf_header.e_shoff.value.value == 0:
        return []
    file.seek(elf_header.e_shoff.value.value)

    elf_sections = [
        read_file_from_struct(file, globals()["SectionHeader" + elf_classe])
        for _ in range(elf_header.e_shnum.value.value)
    ]  # 获取所有section 表
    sections = []
    headers_names_table_address = elf_sections[
        elf_header.e_shstrndx.value.value
    ].sh_offset.value

    organize_sections = {}
    # 声明一下, 这里的写法需要修改一下
    organize_sections['SHT_PROGBITS'] = {}
    organize_sections['SHT_NOTE'] = {}
    organize_sections['SHT_GNU_HASH'] = {}
    organize_sections['SHT_DYNSYM'] = {}
    organize_sections['SHT_STRTAB'] = {}
    organize_sections['SHT_GNU_versym'] = {}
    organize_sections['SHT_GNU_verdneed'] = {}
    organize_sections['SHT_RELA'] = {}
    organize_sections['SHT_INIT_ARRAY'] = {}
    organize_sections['SHT_FINI_ARRAY'] = {}
    organize_sections['SHT_DYNAMIC'] = {}
    organize_sections['SHT_NOBITS'] = {}
    organize_sections['SHT_SYMTAB'] = {}

    for elf_section in elf_sections:
        position = file.tell()
        file.seek(headers_names_table_address + elf_section.sh_name.value)
        name = read_string_fromfile(file)  #读取section字符串的名字
        elf_section.name = FileString(name.value.decode("latin-1"))
        elf_section.name._start_position_ = (
                headers_names_table_address + elf_section.sh_name.value
        )
        elf_section.name._end_position_ = file.tell()
        elf_section.name._data_ = name.value + b"\0"
        file.seek(position)

        elf_section.sh_name = Field(
            elf_section.sh_name, "Section name position"
        )

        elf_section.sh_type = enum_from_value(
            elf_section.sh_type, SectionHeaderType
        )

        elf_section.flags = [
            *enum_from_flags(elf_section.sh_flags, SectionAttributeFlags, " :rwx...")
        ]

        elf_section.sh_addr = Field(
            elf_section.sh_addr, "Section memory address"
        )

        elf_section.sh_offset = Field(
            elf_section.sh_offset, "Section file offset"
        )

        elf_section.sh_size = Field(
            elf_section.sh_size, "Section size in bytes"
        )

        elf_section.sh_link = Field(elf_section.sh_link, "Section link")
        elf_section.sh_info = Field(elf_section.sh_info, "Section info")

        elf_section.sh_addralign = Field(
            elf_section.sh_addralign,
            "Section without alignment"
            if elf_section.sh_addralign.value in (1, 0)
            else "Section alignment",
        )

        elf_section.sh_entsize = Field(
            elf_section.sh_entsize,
            "No section symbal table"
            if elf_section.sh_entsize.value == 0
            else "Symbol table entry size",
        )

        #section name 可能是空的
        if elf_section.sh_type.value.value == SectionHeaderType.SHT_PROGBITS.value:
            update_dict(organize_sections['SHT_PROGBITS'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_NOTE.value:
            update_dict(organize_sections['SHT_NOTE'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_GNU_HASH.value:
            update_dict(organize_sections['SHT_GNU_HASH'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_DYNSYM.value:
            update_dict(organize_sections['SHT_DYNSYM'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_STRTAB.value:
            update_dict(organize_sections['SHT_STRTAB'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_GNU_versym.value:
            update_dict(organize_sections['SHT_GNU_versym'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_GNU_verdneed.value:
            update_dict(organize_sections['SHT_GNU_verdneed'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_RELA.value:
            update_dict(organize_sections['SHT_RELA'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_INIT_ARRAY.value:
            update_dict(organize_sections['SHT_INIT_ARRAY'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_FINI_ARRAY.value:
            update_dict(organize_sections['SHT_FINI_ARRAY'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_DYNAMIC.value:
            update_dict(organize_sections['SHT_DYNAMIC'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_NOBITS.value:
            update_dict(organize_sections['SHT_NOBITS'], elf_section.name, elf_section)
        elif elf_section.sh_type.value.value == SectionHeaderType.SHT_SYMTAB.value:
            update_dict(organize_sections['SHT_SYMTAB'], elf_section.name, elf_section)

        # if entropy_charts_import:
        #     sections.append(
        #         Section(
        #             elf_section.name,
        #             elf_section.sh_offset.value,
        #             elf_section.sh_size.value,
        #         )
        #     )

    return (
        elf_sections,
        organize_sections
    )



def gnu_hash(s: str):
    h=c_uint32(5381)
    for c in s:
        h.value = h.value + h.value * 32 + ord(c)
    return h.value

def sysv_hash(s:str):

    h = c_uint32(0)
    for c in s:
        h.value = 16 * h.value + ord(c)
        h.value = h.value ^ ((h.value >> 24) & 0xf0)
    return h.value & 0xfffffff


def lookup_in_hash_tab(
        func_name: str,
        symbols_list: List[Union[SymbolTableEntry32, SymbolTableEntry64]],
        hash_tab: HashTable,
):
    if hash_tab is None:
        return [0, None]

    hash = sysv_hash(func_name)

    nbuckets = hash_tab.nbucket.value
    #nchains = hash_tab.nchain.value
    buckets = hash_tab.buckets
    chains = hash_tab.chains

    i = buckets[ hash % nbuckets].value

    while i!=0:
        if func_name == symbols_list[i].name:
            return [i, symbols_list[i]]
        i=chains[i].value

    return [0, None]


def lookup_in_gnu_hash_tab(
        func_name: str,
        symbols_list: List[Union[SymbolTableEntry32,SymbolTableEntry64]] ,
        gnu_hash_tab: GnuHashTable,
        elf_class:str):

    if gnu_hash_tab is None:
        return [0, None]
    size_t_bitlen = 4 * 8
    if elf_class == "64":
        size_t_bitlen = size_t_bitlen * 2

    # step_1 prepare
    hash1=gnu_hash(func_name)
    hash1_div = hash1 // size_t_bitlen
    hash1_mod_mask = 1 << (hash1 % size_t_bitlen)

    # step_2 gnu_lookup_filtered()
    bloomSize = gnu_hash_tab.bloomSize.value
    bloomShift = gnu_hash_tab.bloomShift.value
    blooms = gnu_hash_tab.blooms
    bloom = blooms[hash1_div & (bloomSize - 1)].value
    if bloom & hash1_mod_mask == 0:
        return [0,None]
    bloom = bloom >> (hash1 >> bloomShift) % size_t_bitlen
    if bloom & 1 ==0 :
        return [0,None]

    # step_3 gnu_lookup()
    nbucket = gnu_hash_tab.nbucket.value
    symndx = gnu_hash_tab.symndx.value
    buckets = gnu_hash_tab.buckets
    chanis = gnu_hash_tab.chains

    i = buckets[hash1 % nbucket].value
    if i == 0:
        return [0,None]

    hashval = chanis[i-symndx:]
    hash1 = hash1 | 1 # hash1 被修改了
    while True:
        chani = hashval[0].value
        # if hash1 == (chani | 1) and func_name == symbols_list[i].st_name.value.decode('utf-8'):
        if hash1 == (chani | 1) and func_name == symbols_list[i].name:
            return [i,symbols_list[i]]
        i = i + 1
        hashval = hashval[1:]
        if chani & 1 != 0:# 我们的gnu_hash_tab.chains获取方式可能不太对,导致出现bug,以后再修复
            break
        # 自定义添加的bug处理
    return [0, None]


def mm_dlsym(
        api_name,
        symbols_list: List[Union[SymbolTableEntry32,SymbolTableEntry64]] ,
        hash_tab,
        gnu_hash_tab,
        elf_class):

    if gnu_hash_tab is not None:
        [idx,sym] = lookup_in_gnu_hash_tab(api_name, symbols_list, gnu_hash_tab,elf_class)
        #[idx, sym] = lookup_in_hash_tab(api_name, symbols_list, hash_tab)
        return [idx,sym]
    elif hash_tab is not None:
        [idx, sym] = lookup_in_hash_tab(api_name, symbols_list, hash_tab)
        return [idx, sym]
    else:
        raise ValueError("no hash table")



# section_headers :List[Union[SectionHeader32, SectionHeader64]],
# symtabs: Dict[str,Dict[str, Union[SectionHeader32, SectionHeader64]]],
# List[Dict[str, Any]]

# strtab_offset,strtab_size,symtab,symtab_size: None
def parse_elf_symbol(
        file: _BufferedIOBase,
        strsym_item: SYMBOL_ITEM,
        elf_classe: str,
):
    """
    This function parses ELF symbols table.
    """
    sym_list = []
    sym_list_bind_organize = {}
    sym_list_type_organize = {}
    sym_list_visibility_organize = {}

    strtab = strsym_item.strtab
    symtab = strsym_item.symtab

    #section_header_symtab :Union[SectionHeader32, SectionHeader64] =value
    #section_header_strtab = section_headers[section_header_symtab.sh_link.value.value]

    file.seek(strtab['d_offset'])
    strtab_file = BytesIO(file.read(strtab['d_size']))

    symtab_strut = globals()["SymbolTableEntry" + elf_classe]
    symtab_struct_size = sizeof(symtab_strut)

    file.seek(symtab['d_offset'])
    sym_cnt = symtab['d_size'] // symtab_struct_size
    for _ in range(sym_cnt ):
        symbol = read_file_from_struct(file, symtab_strut)
        symbol.st_value = Field(symbol.st_value, "Symbol table value")

        symbol.st_size = Field(symbol.st_size, "Symbol table size")

        symbol.st_shndx = enum_from_value(
            symbol.st_shndx, SpecialSectionIndexes
        )

        #这好像是临时给class添加成员....
        # 这种数据类型的强大之处 是可以动态添加成员....
        # symbol.st_bind = enum_from_value(
        #     c_byte(symbol.st_info.value >> 4), SymbolBinding
        # )
        #
        # symbol.st_type = enum_from_value(
        #     c_byte(symbol.st_info.value & 0xF), SymbolType
        # )
        #
        # symbol.st_visibility = enum_from_value(
        #     c_byte(symbol.st_other.value & 0x3), SymbolVisibility
        # )
        symbol.st_info.st_bind = enum_from_value(
            c_byte(symbol.st_info.value >> 4), SymbolBinding
        )
        symbol.st_info.st_type = enum_from_value(
            c_byte(symbol.st_info.value & 0xF), SymbolType
        )
        symbol.st_other.st_visibility = enum_from_value( #这个是来自st_other
             c_int32(symbol.st_other.value & 0x3) #听说该字段恒为0
             ,SymbolVisibility
        )

        strtab_file.seek(symbol.st_name.value)
        start_position = symbol.st_name.value + strtab['d_offset']
        symbol.st_name = read_string_fromfile(strtab_file)
        symbol.name = FileString(symbol.st_name.value.decode("latin-1"))
        symbol.name._start_position_ = start_position
        symbol.name._end_position_ = (symbol.name._start_position_ + len(symbol.name) + 1)  # 意思是说在文件的什么位置
        symbol.name._data_ = symbol.st_name.value + b"\0"

        sym_list.append(symbol)
        if symbol.st_info.st_bind.information not in sym_list_bind_organize:
            sym_list_bind_organize[symbol.st_info.st_bind.information] = []
        if symbol.st_info.st_type.information not in sym_list_type_organize:
            sym_list_type_organize[symbol.st_info.st_type.information] = []
        if symbol.st_other.st_visibility.information not in sym_list_visibility_organize:
            sym_list_visibility_organize[symbol.st_other.st_visibility.information] = []

        sym_list_bind_organize[symbol.st_info.st_bind.information].append(symbol)
        sym_list_type_organize[symbol.st_info.st_type.information].append(symbol)
        sym_list_visibility_organize[symbol.st_other.st_visibility.information].append(symbol)


    return {
            'list': sym_list,
            'sort':
                {
                    'bind': sym_list_bind_organize,
                    'mm_type': sym_list_type_organize,
                    'visibility': sym_list_visibility_organize
                }
        }



# def parse_elfcomment( #属于节
#         file: _BufferedIOBase,
#         comment_section: Union[SectionHeader32, SectionHeader64],
# ) -> Iterable[bytes]:
#     """
#     This function parses ELF comment section.
#     """
#
#     if comment_section:
#         position = file.seek(comment_section.sh_offset.value.value)
#
#         for data in file.read(comment_section.sh_size.value.value).split(
#                 b"\0"
#         ):
#             if data:
#                 data = FileBytes(data + b"\0")
#                 data._start_position_ = position
#                 data._end_position_ = position + len(data) + 1
#                 data.string = data.decode("latin-1")
#                 yield data
#                 position += len(data) + 1
#             else:
#                 position += 1


def parse_elfnote(
        file: _BufferedIOBase,
        note_sections: List[Union[SectionHeader32, SectionHeader64]],
        elf_classe: str,
) -> Iterable[Union[Note32, Note64]]:
    """
    This function parses ELF note sections.
    """

    for note_sec in note_sections:
        file.seek(note_sec.sh_offset.value.value)
        note = read_file_from_struct(file, globals()["Note" + elf_classe])

        position = file.tell()
        note.name = FileBytes(
            file.read(
                note.name_size.value
                + get_padding_length(note.name_size.value, 4)
            )
        )
        note.name.string = note.name.decode("latin-1")
        note.name._start_position_ = position
        note.name._end_position_ = file.tell()
        position = file.tell()
        note.descriptor = FileBytes(
            file.read(
                note.descriptor_size.value
                + get_padding_length(note.name_size.value, 4)
            )
        )
        note.descriptor._start_position_ = position
        note.descriptor._end_position_ = file.tell()

        yield note


# 有一点需要注意, dynamic d_tag 解析出来的类型好像都没有重复的, 那就默认为1吧
def parse_elf_dynamic(
        file: _BufferedIOBase,
        dynamic_programs: List[Union[ProgramHeader32, ProgramHeader64]],
        elf_classe: str,
) -> Tuple[
    List[Union[Dynamic32, Dynamic64]],
    Dict[str, Union[Dynamic32, Dynamic64]]
]:
    """
    This function parses ELF dynamic section.
    """

    if dynamic_programs is None or len(dynamic_programs) == 0:
        return None
    dyn_items = []
    dyn_items_organize = {}
    dyn_items_organize['UN_DEFINED'] = []
    # 如果有不关心,或者未定义的怎么办??? 会被覆盖更新的


    for dynamic_program in dynamic_programs:
        file.seek(dynamic_program.p_offset.value.value)
        d_tag = 1
        while d_tag:
            position = file.tell()
            dyn_item = read_file_from_struct(file, globals()["Dynamic" + elf_classe])
            dyn_item.d_tag = enum_from_value(dyn_item.d_tag, DynamicType)
            dyn_item.d_tag._start_position_ = position
            dyn_item.d_tag._end_position_ = position + sizeof(dyn_item.d_tag.value)

            if dyn_item.d_tag.value.value != DynamicType.DT_FLAGS.value:
                dyn_item.d_value._start_position_ = position + sizeof(dyn_item.d_tag.value)
                dyn_item.d_value._end_position_ = file.tell()
            else:
                # 非常规处理
                dyn_item.d_value.flags = []
                for flag in enum_from_flags(dyn_item.d_value, DynamicFlags):
                    flag._start_position_ = position + sizeof(
                        dyn_item.d_tag.value
                    )
                    flag._end_position_ = file.tell()
                    dyn_item.d_value.flags.append(flag)

            d_tag = dyn_item.d_tag.value.value
            dyn_items.append(dyn_item)
            if dyn_item.d_tag.information == "UN_DEFINED":
                dyn_items_organize['UN_DEFINED'].append(dyn_item) #不关心的,其他的
            else:
                dyn_items_organize[dyn_item.d_tag.information] = dyn_item

        return (dyn_items, dyn_items_organize)

def parse_elf_relTable(
        file: _BufferedIOBase,
        dyn_items_organize,
        machine_type: str,
        dyn_symbol_organize,
        elf_classe: str):

    Relocation_Tables = {}
    Relocation_Tables_organize = {}

    rel_type_id = dyn_items_organize['DT_PLTREL'].d_value.value
    reltype_with_addend = False
    rel_type_name = 'DT_REL'

    if rel_type_id == 7: #DT_RELA
        rel_type = globals()["RelocationAddend" + elf_classe]
        rel_type_size=sizeof(rel_type)
        if 'DT_RELAENT' in dyn_items_organize and rel_type_size != dyn_items_organize['DT_RELAENT'].d_value.value:
            raise Exception("unknown relocation mm_type size")
        reltype_with_addend = True


    elif rel_type_id == 17: #DT_REL
        rel_type = globals()["Relocation" + elf_classe]
        rel_type_size=sizeof(rel_type)
        if 'DT_RELENT' in dyn_items_organize and rel_type_size != dyn_items_organize['DT_RELENT'].d_value.value:
            raise Exception("unknown relocation mm_type size")
        rel_type = globals()["Relocation" + elf_classe]
    else:
        raise Exception("unknown relocation mm_type")


    if 'DT_JMPREL' in dyn_items_organize:
        jmp_rel_table_offset = dyn_items_organize['DT_JMPREL'].d_value.value
        file.seek(jmp_rel_table_offset)
        jmp_rel_table = [
            read_file_from_struct(file, rel_type)
            for _ in range(dyn_items_organize['DT_PLTRELSZ'].d_value.value // rel_type_size)
        ]
        Relocation_Tables['DT_JMPREL'] = jmp_rel_table

    if reltype_with_addend:
        rel_type_name = 'DT_RELA'

    if rel_type_name in dyn_items_organize:
        rel_table_offset = dyn_items_organize[rel_type_name].d_value.value
        file.seek(rel_table_offset)
        rel_table = [
            read_file_from_struct(file, rel_type)
            for _ in range(dyn_items_organize[rel_type_name+'SZ'].d_value.value // rel_type_size)
        ]
        Relocation_Tables[rel_type_name] = rel_table

    shift_value = 8
    and_value = 0xff
    #r_type =c_uint8(0)
    if elf_classe == '64':
        shift_value = 32
        and_value = 0xffffffff

    for key,value in Relocation_Tables.items():
        Relocation_Tables_organize_i = {}
        for j in value:
            r_sym_value = c_int32(j.r_info.value>>shift_value)
            j.r_info.R_SYM = Field(
                value=r_sym_value.value,#注意这里故意默认int32
                information=dyn_symbol_organize['list'][r_sym_value.value].name)
            j.r_info.R_TYPE = enum_from_value(
                c_int32(j.r_info.value & and_value),#注意这里故意默认int32
                globals()[machine_type.replace("EM","RelType")])

            if j.r_info.R_TYPE.information not in Relocation_Tables_organize_i:
                Relocation_Tables_organize_i[j.r_info.R_TYPE.information] = []
            Relocation_Tables_organize_i[j.r_info.R_TYPE.information].append(j)
        Relocation_Tables_organize[key] = Relocation_Tables_organize_i

    return (
        Relocation_Tables,
        Relocation_Tables_organize
    )





def parse_elffile(
        file: _BufferedIOBase,
):
    """
    This function parses ELF file.
    主要section是可选项,以至于我需要做一个兼容的处理
    """

    (
        elf_indent,
        elf_classe
    ) = parse_elfheader_ident(file)  #处理elf-indent[16]的信息
    elf_headers = parse_elfheader(file,
                                  elf_classe)  #和parse_elfheader_ident(file)有点重复,但也不重复, 因为parse_elfheader_ident(file)确定了我们的x86和x64

    # programs
    (
        programs_headers,
        programs_headers_organize
    ) = parse_program_headers(file, elf_headers, elf_classe)

    (
        dyn_items,
        dyn_items_organize
    ) = parse_elf_dynamic(file, programs_headers_organize["PT_DYNAMIC"], elf_classe)

    # 解析动态符号也需要用到这个
    (
        hash_table,
        dynsym_cnt_inHash
    ) = parse_dynamic_HASH(file, dyn_items_organize)

    # 目前来看, 应该放在dynamic symbol 解析之后
    (
        gnu_hash_table,
        dynsym_cnt_inGNUHash
    ) = parse_dynamic_GNU_HASH(file, dyn_items_organize, elf_classe)

    if hash_table is not None and gnu_hash_table is not None:
        if dynsym_cnt_inHash != dynsym_cnt_inGNUHash:
            raise ValueError("dynsym_cnt_inHash != dynsym_cnt_inGNUHash")
    dynsym_cnt = dynsym_cnt_inHash | dynsym_cnt_inGNUHash

    # 还需要进一步整理代码
    # 也就所说,下面的代码不应该只是处理dynamic
    symbol_items = {
        ".dynamic": SYMBOL_ITEM(
            dyn_items_organize['DT_STRTAB'].d_value.value,
            dyn_items_organize['DT_STRSZ'].d_value.value,
            dyn_items_organize['DT_SYMTAB'].d_value.value,
            dynsym_cnt * dyn_items_organize['DT_SYMENT'].d_value.value,
        )
    }

    symbol_items_organize = {
        ".dynamic": parse_elf_symbol(
            file,
            symbol_items[".dynamic"],
            elf_classe,
        )
    }
    (
        Relocation_Tables,
        Relocation_Tables_organize
    )=parse_elf_relTable(file, dyn_items_organize, elf_headers.e_machine.information,symbol_items_organize[".dynamic"],elf_classe )
    # sections

    # (
    #     section_headers,
    #     section_headers_organize
    # ) = parse_sections_headers(file, elf_headers, elf_classe)
    # pass

    # Optionnal sections analysis

    #comments = [*parse_elfcomment(file, comment_section)]
    #notes = [*parse_elfnote(file, note_sections, elf_classe)]

    return [
        elf_indent,
        elf_classe,
        elf_headers,
        programs_headers,
        programs_headers_organize,
        dyn_items,
        dyn_items_organize,
        hash_table,
        gnu_hash_table,
        dynsym_cnt,
        symbol_items,
        symbol_items_organize,
        Relocation_Tables,
        Relocation_Tables_organize
    ]
