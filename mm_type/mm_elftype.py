
from ctypes import (
    c_byte,
    c_ubyte,
    c_uint16,
    c_int32,
    c_uint32,
    c_int64,
    c_uint64,
    c_char,
)

from mm_type import BaseStructure


def structure(cls: type) -> type:
    """
    This decorator helps to build C Structures.
    """

    def wrap(cls: type) -> type:
        """
        This function builds the C Structure class.
        """

        return type(
            cls.__name__,
            (cls, BaseStructure),
            {"__annotations__": cls.__annotations__},
        )

    return wrap(cls)


class Elf32_Addr(c_uint32):
    pass


class Elf32_Half(c_uint16):
    pass


class Elf32_Section(c_uint16):
    pass


class Elf32_Versym(c_uint16):
    pass


class Elf32_Off(c_uint32):
    pass


class Elf32_Sword(c_int32):
    pass


class Elf32_Word(c_uint32):
    pass


@structure
class mm_Elf32_Word:
    item: Elf32_Word


class Elf32_Sxword(c_int64):
    pass


class Elf32_Xword(c_uint64):
    pass


class Elf64_Addr(c_uint64):
    pass


class Elf64_Half(c_uint16):
    pass


class Elf64_Section(c_uint16):
    pass


class Elf64_Versym(c_uint16):
    pass


class Elf64_Off(c_uint64):
    pass


class Elf64_Sword(c_int32):
    pass


class Elf64_Word(c_uint32):
    pass


class Elf64_Sxword(c_int64):
    pass


class Elf64_Xword(c_uint64):
    pass


@structure
class mm_Elf64_Xword:
    item: Elf64_Xword


@structure
class ElfIdent:
    ei_mag: c_char * 4
    ei_class: c_ubyte
    ei_data: c_ubyte
    ei_version: c_ubyte
    ei_osabi: c_ubyte
    ei_abiversion: c_ubyte
    ei_pad: c_char
    ei_nident: c_char * 6


@structure
class ElfHeader32:
    e_ident: ElfIdent
    e_type: Elf32_Half
    e_machine: Elf32_Half
    e_version: Elf32_Word
    e_entry: Elf32_Addr
    e_phoff: Elf32_Off
    e_shoff: Elf32_Off
    e_flags: Elf32_Word
    e_ehsize: Elf32_Half
    e_phentsize: Elf32_Half
    e_phnum: Elf32_Half
    e_shentsize: Elf32_Half
    e_shnum: Elf32_Half
    e_shstrndx: Elf32_Half


@structure
class ElfHeader64:
    e_ident: ElfIdent
    e_type: Elf64_Half
    e_machine: Elf64_Half
    e_version: Elf64_Word
    e_entry: Elf64_Addr
    e_phoff: Elf64_Off
    e_shoff: Elf64_Off
    e_flags: Elf64_Word
    e_ehsize: Elf64_Half
    e_phentsize: Elf64_Half
    e_phnum: Elf64_Half
    e_shentsize: Elf64_Half
    e_shnum: Elf64_Half
    e_shstrndx: Elf64_Half


@structure
class ProgramHeader32:
    p_type: Elf32_Word
    p_offset: Elf32_Off
    p_vaddr: Elf32_Addr
    p_paddr: Elf32_Addr
    p_filesz: Elf32_Word
    p_memsz: Elf32_Word
    p_flags: Elf32_Word
    p_align: Elf32_Word


@structure
class ProgramHeader64:
    p_type: Elf64_Word
    p_flags: Elf64_Word
    p_offset: Elf64_Off
    p_vaddr: Elf64_Addr
    p_paddr: Elf64_Addr
    p_filesz: Elf64_Xword
    p_memsz: Elf64_Xword
    p_align: Elf64_Xword


@structure
class SectionHeader32:
    sh_name: Elf32_Word
    sh_type: Elf32_Word
    sh_flags: Elf32_Word
    sh_addr: Elf32_Addr
    sh_offset: Elf32_Off
    sh_size: Elf32_Word
    sh_link: Elf32_Word
    sh_info: Elf32_Word
    sh_addralign: Elf32_Word
    sh_entsize: Elf32_Word


@structure
class SectionHeader64:
    sh_name: Elf64_Word
    sh_type: Elf64_Word
    sh_flags: Elf64_Xword
    sh_addr: Elf64_Addr
    sh_offset: Elf64_Off
    sh_size: Elf64_Xword
    sh_link: Elf64_Word
    sh_info: Elf64_Word
    sh_addralign: Elf64_Xword
    sh_entsize: Elf64_Xword


@structure
class SymbolTableEntry32:
    st_name: Elf32_Word
    st_value: Elf32_Addr
    st_size: Elf32_Word
    st_info: c_byte
    st_other: c_byte
    st_shndx: Elf32_Half


@structure
class SymbolTableEntry64:
    st_name: Elf64_Word
    st_info: c_byte
    st_other: c_byte
    st_shndx: Elf64_Half
    st_value: Elf64_Addr
    st_size: Elf32_Xword

@structure
class Note32:
    name_size: Elf32_Word
    descriptor_size: Elf32_Word
    type: Elf32_Word


@structure
class Note64:
    name_size: Elf64_Word
    descriptor_size: Elf64_Word
    type: Elf64_Word


@structure
class Dynamic32:
    d_tag: Elf32_Sword
    d_value: Elf32_Word  # untion [value,d_ptr]


@structure
class Dynamic64:
    d_tag: Elf64_Sxword
    d_value: Elf64_Xword  # untion [value,d_ptr]


@structure
class HashTable:
    nbucket: Elf32_Word
    nchain: Elf32_Word
    buckets = None
    chains = None


@structure
class GnuHashTable:
    nbucket: Elf32_Word
    symndx: Elf32_Word
    bloomSize: Elf32_Word
    bloomShift: Elf32_Word
    blooms = None
    buckets = None
    chains = None


class SYMBOL_ITEM:
    strtab: {}
    symtab: {}

    def __init__(self, srt_off, str_size, sym_off, sym_size):
        self.strtab = {'d_offset': srt_off, 'd_size': str_size}
        self.symtab = {'d_offset': sym_off, 'd_size': sym_size}



@structure
class Relocation32: #8
    r_offset: Elf32_Addr
    r_info: Elf32_Word

@structure
class Relocation64: #16
    r_offset: Elf64_Addr
    r_info: Elf64_Xword
@structure
class RelocationAddend32:# 12
    r_offset: Elf32_Addr
    r_info: Elf32_Word
    r_addend: Elf32_Sword
@structure
class RelocationAddend64: #24
    r_offset: Elf64_Addr
    r_info: Elf64_Xword
    r_addend: Elf32_Sxword
