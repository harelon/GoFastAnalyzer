import re

import ida_ua
import ida_idp
import ida_enum
import ida_name
import ida_bytes
import ida_funcs
import ida_allins
import ida_struct
import ida_hexrays
import ida_typeinf
from idc import BADADDR


from DecompilerLib.GoCallinfo import GoCall
from DecompilerLib.utils import BYTE_SIZE


def translate(string: str, translation_dict: dict) -> str:
    for key, value in translation_dict.items():
        string = string.replace(key, value)
    return string


class RtypeCall:
    """
    Has {type} as variable in the definition to help create formatted structures
    """

    type_header = "RTYPE_"

    def __init__(self, definition: str) -> None:
        self.definition = definition
        self.type_based_definition = re.compile("((.*?){type}(.*?))\\s")
        self.initialized = False

    def init(self) -> None:
        self.initialized = True

    def get_referenced_rtype(self, ea: int) -> tuple[str, int]:
        """Returns the name of the rtype that is initialized before this ea"""
        wanted_outtype = "char *"
        func = ida_funcs.get_func(ea)
        # get the name of the type initialized here
        insn = ida_ua.insn_t()
        prev_address = ida_ua.decode_prev_insn(insn, ea)
        while prev_address < func.start_ea:
            if insn.get_canon_feature() & ida_idp.CF_CALL != 0:
                break
            if (
                insn.itype != ida_allins.NN_nop
                and insn.itype != ida_allins.NN_fnop
                and not (
                    insn.itype == ida_allins.NN_xchg and insn.Op1.reg == insn.Op2.reg
                )
                and insn.Op2.addr != 0
            ):
                out_name = ida_name.get_name(insn.Op2.addr)
                if out_name.startswith(self.type_header):
                    wanted_outtype = out_name[len(self.type_header) :]
                    return wanted_outtype, insn.Op2.addr

            prev_address = ida_ua.decode_prev_insn(insn, prev_address)
        return None

    def fill_vars(self, ea: int) -> dict[str, str]:
        result = self.get_referenced_rtype(ea)
        if result is None:
            return None

        starting_dict = {"{type}": result[0]}

        typedef = self.type_based_definition.search(self.definition)

        # if we have we a formatted declaration which contains the {type}
        # and a slice is created from it but the slice type doesn't exist in the local typedefs
        # then create it from the information we know
        if typedef:
            translated_definition = translate(typedef.group(1), starting_dict)
            if (
                ida_typeinf.get_named_type(
                    None, translated_definition, ida_typeinf.NTF_TYPE
                )
                is None
            ):
                if typedef.group(2) == "_slice_":
                    my_slice = ida_struct.get_struc(
                        ida_struct.add_struc(BADADDR, translated_definition)
                    )
                    ida_struct.add_struc_member(
                        my_slice,
                        "ptr",
                        BADADDR,
                        ida_bytes.qword_flag(),
                        None,
                        8,
                    )

                    tinfo = ida_typeinf.tinfo_t()
                    ida_typeinf.parse_decl(
                        tinfo, None, f"{starting_dict['{type}']};", 0
                    )

                    # set the ptr member type to be a pointer to our RTYPE
                    ptr_tinfo = ida_typeinf.tinfo_t()
                    ptr_tinfo.create_ptr(tinfo)
                    mem = ida_struct.get_member(my_slice, 0)
                    ida_struct.set_member_tinfo(my_slice, mem, 0, ptr_tinfo, 0)

                    ida_struct.add_struc_member(
                        my_slice,
                        "len",
                        BADADDR,
                        ida_bytes.qword_flag(),
                        None,
                        8,
                    )
                    ida_struct.add_struc_member(
                        my_slice,
                        "cap",
                        BADADDR,
                        ida_bytes.qword_flag(),
                        None,
                        8,
                    )

        return starting_dict

    def get_decl_mi(
        self, mba: ida_hexrays.mba_t, call_ea: int, callee_ea: int
    ) -> ida_hexrays.mcallinfo_t:
        translator = self.fill_vars(call_ea)
        if translator is None:
            return None

        actual_definition = translate(self.definition, translator)
        tinfo = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(tinfo, None, actual_definition, ida_typeinf.PT_SIL)
            is None
        ):
            print(f'Error parsing -> "{actual_definition}" at {hex(call_ea)}')
            return

        callinfo = GoCall(mba, callee_ea, tinfo)
        return callinfo.callinfo


class MapCall(RtypeCall):
    """
    Has variables to help create formatted structures\n
    {type} is the map's type\n
    {key} is the map's key's type\n
    {value} is the map's value's type\n
    """

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.search_pattern = re.compile("\[(.*?)\](.*)$")

    def init(self) -> None:
        super().init()
        # if we don't have type definitions we can't parse the rtype for the mapcall
        self.rtype_tinfo = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(self.rtype_tinfo, None, "RTYPE;", ida_typeinf.PT_SIL)
            is None
        ):
            self.disabled = True
            return

        self.maptype_tinfo = ida_typeinf.tinfo_t()
        if (
            ida_typeinf.parse_decl(
                self.maptype_tinfo, None, "MAP_TYPE;", ida_typeinf.PT_SIL
            )
            is None
        ):
            self.disabled = True
            return

        self.disabled = False
        key = ida_typeinf.udt_member_t()
        key.name = "key"
        self.maptype_tinfo.find_udt_member(key, ida_typeinf.STRMEM_NAME)
        self.key_offset = key.offset // BYTE_SIZE
        self.key_size = key.size // BYTE_SIZE

        elem = ida_typeinf.udt_member_t()
        elem.name = "elem"
        self.maptype_tinfo.find_udt_member(elem, ida_typeinf.STRMEM_NAME)
        self.elem_offset = elem.offset // BYTE_SIZE
        self.elem_size = elem.size // BYTE_SIZE

        kind = ida_typeinf.udt_member_t()
        kind.name = "kind"
        self.rtype_tinfo.find_udt_member(kind, ida_typeinf.STRMEM_NAME)
        self.kind_offset = kind.offset // BYTE_SIZE
        self.kind_size = kind.size // BYTE_SIZE

        self.kind_func = ida_enum.get_enum_member_value(
            ida_enum.get_enum_member_by_name("KIND_FUNC")
        )
        self.kind_mask = ida_enum.get_enum_member_bmask(
            ida_enum.get_enum_member_by_name("KIND_FUNC")
        )

    def fill_vars(self, ea: int) -> dict[str, str] | None:
        if not self.initialized:
            self.init()

        starting_dict = super().fill_vars(ea)
        if starting_dict is None or self.disabled:
            return

        _, addr = self.get_referenced_rtype(ea)
        map_type_addr = addr + self.rtype_tinfo.get_size()

        key_rtype_addr = int.from_bytes(
            ida_bytes.get_bytes(map_type_addr + self.key_offset, self.key_size),
            "little",
        )
        elem_rtype_addr = int.from_bytes(
            ida_bytes.get_bytes(map_type_addr + self.elem_offset, self.elem_size),
            "little",
        )

        key_type = ida_name.get_name(key_rtype_addr)[len(self.type_header) :]
        elem_type = ida_name.get_name(elem_rtype_addr)[len(self.type_header) :]

        elem_kind = int.from_bytes(
            ida_bytes.get_bytes(elem_rtype_addr + self.kind_offset, self.kind_size),
            "little",
        )

        if elem_kind & self.kind_mask == self.kind_func:
            elem_type = f"PTR_{elem_type}"

        starting_dict["{key}"] = key_type
        starting_dict["{value}"] = elem_type
        return starting_dict


known_functions: dict[str, RtypeCall] = {
    "runtime.typedmemmove": RtypeCall(
        "{type} * typedmemmove(RTYPE * _typ, {type} *, {type} *);"
    ),
    "runtime.newobject": RtypeCall("{type} * newobject(RTYPE * _typ);"),
    "runtime.makeslice": RtypeCall(
        "_slice_{type} * makeslice(RTYPE * _typ, __int32, __int32);"
    ),
    "runtime.makeslice64": RtypeCall(
        "_slice_{type} * makeslice64(RTYPE * _typ, __int64, __int64);"
    ),
    "runtime.makeslicecopy": RtypeCall(
        "_slice_{type} * makeslicecopy(RTYPE * _typ, int, int, {type} *);"
    ),
    "runtime.growslice": RtypeCall(
        "_slice_{type} growslice(_slice_{type}, int, RTYPE * _typ);"
    ),
    "runtime.convT": RtypeCall(
        "{type} * convT(RTYPE * _typ, {type} *);",
    ),
    "runtime.makemap64": RtypeCall(
        "{type} * makemap64(RTYPE * _typ, __int64, {type});",
    ),
    "runtime.makemap": RtypeCall(
        "{type} * makemap(RTYPE * _typ, int, {type});",
    ),
    "runtime.mapaccess1": MapCall(
        "{value} * mapaccess1(RTYPE * _typ, {type}, {key} *);",
    ),
    "runtime.mapaccess1_fast32": MapCall(
        "{value} * mapaccess1_fast32(RTYPE * _typ, {type}, __int32);",
    ),
    "runtime.mapaccess1_fast64": MapCall(
        "{value} * mapaccess1_fast64(RTYPE * _typ, {type}, __int64);",
    ),
    "runtime.mapaccess1_faststr": MapCall(
        "{value} * mapaccess1_faststr(RTYPE * _typ, {type}, string);",
    ),
    "runtime.mapaccess1_fat": MapCall(
        "{value} * mapaccess1_fat(RTYPE * _typ, {type}, {key} *, char *);",
    ),
    "runtime.mapassign": MapCall(
        "{value} * mapassign(RTYPE * _typ, {type}, {key} *);",
    ),
    "runtime.mapassign_fast32": MapCall(
        "{value} * mapassign_fast64(RTYPE * _typ, {type}, __int32);",
    ),
    "runtime.mapassign_fast32ptr": MapCall(
        "{value} * mapassign_fast64(RTYPE * _typ, {type}, __int32 *);",
    ),
    "runtime.mapassign_fast64": MapCall(
        "{value} * mapassign_fast64(RTYPE * _typ, {type}, __int64);",
    ),
    "runtime.mapassign_fast64ptr": MapCall(
        "{value} * mapassign_fast64(RTYPE * _typ, {type}, __int64 *);",
    ),
    "runtime.mapassign_faststr": MapCall(
        "{value} * mapassign_faststr(RTYPE * _typ, {type}, string);",
    ),
    "runtime.mapdelete": MapCall(
        "void mapdelete(RTYPE * _typ, {type}, {key} *);",
    ),
    "runtime.mapdelete_fast32": MapCall(
        "void mapdelete_fast32(RTYPE * _typ, {type}, __int32);",
    ),
    "runtime.mapdelete_fast64": MapCall(
        "void mapdelete_fast64(RTYPE * _typ, {type}, __int64);",
    ),
    "runtime.mapdelete_faststr": MapCall(
        "void mapdelete_faststr(RTYPE * _typ, {type}, string);",
    ),
    "runtime.mapclear": MapCall(
        "void mapdelete_faststr(RTYPE * _typ, {type});",
    ),
}
