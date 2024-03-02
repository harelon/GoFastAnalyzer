import ida_idp
import ida_name
import ida_range
import ida_struct
import ida_hexrays
import ida_typeinf

from idc import BADADDR
from ida_kernwin import get_kernel_version

from DecompilerLib.utils import BYTE_SIZE, go_fast_convention


def get_sized_register_by_name(reg_name: str, reg_size: int) -> str:
    """Get register name and wanted size and convert the full register name to one that also represents size"""
    return ida_idp.get_reg_name(ida_idp.str2reg(reg_name), reg_size)


def fill_tinfo(tinfo: ida_typeinf.tinfo_t) -> None:
    """
    Create a new structure without gaps in it from the type info we receive
    """
    sid = ida_struct.add_struc(BADADDR, f"{tinfo.dstr()}_nogaps")
    struc = ida_struct.get_struc(sid)

    gap_range = ida_range.rangeset_t()

    for i in range(tinfo.get_udt_nmembers()):
        # find member
        member = ida_typeinf.udt_member_t()
        member.offset = i
        tinfo.find_udt_member(member, ida_typeinf.STRMEM_INDEX)

        # check member gaps and fill them recursively
        member.type.calc_gaps(gap_range)
        if not gap_range.empty():
            fill_tinfo(member.type)
            member_type = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(
                member_type, None, f"{member.type.dstr()}_nogaps;", ida_typeinf.PT_SIL
            )
        # member has no gaps we can use it as is
        else:
            member_type = member.type

        # convert tinfo information to struct information
        name = ida_name.validate_name(member.name, ida_name.SN_NOCHECK)
        member_size = member.size // BYTE_SIZE
        member_offset = member.offset // BYTE_SIZE

        ida_struct.add_struc_member(struc, name, member_offset, 0, None, member_size)
        mem = ida_struct.get_member(struc, member_offset)
        ida_struct.set_member_tinfo(struc, mem, member_offset, member_type, 0)

    # fill gaps in our current struct
    tinfo.calc_gaps(gap_range)
    for range_item in gap_range:
        ida_struct.add_struc_member(
            struc,
            f"aligning_gap_{hex(range_item.start_ea)}",
            range_item.start_ea,
            0,
            None,
            range_item.end_ea - range_item.start_ea,
        )


class GoTypeAssigner:
    """
    Get a tinfo and iterate it recursively to decide whether it is serializable for being passed through registers
    If so args_sizes list stores how to split it among registers
    """

    def __init__(self, arg_sizes: list) -> None:
        self.arg_sizes = arg_sizes

    # Assign the type into registers or stack
    def assign_type(self, tinfo: ida_typeinf.tinfo_t) -> bool:
        """
        Try to assign the current received type return whether it can be serialized in registers.
        Add member sizes to the arg_size list
        """
        if tinfo.get_size() == 0:
            return True

        subtype_count = tinfo.get_udt_nmembers()
        # the type is atomic
        if subtype_count == -1 and (
            tinfo.is_decl_bool() or tinfo.is_scalar() or tinfo.is_ptr()
        ):
            self.arg_sizes.append(tinfo.get_size())
        elif tinfo.is_decl_array():
            # arrays of 2 and more make the type passed on the stack
            if tinfo.get_array_nelems() > 1:
                self.arg_sizes.clear()
                return False
            # array of one is recursively assigned to registers
            else:
                return self.assign_type(tinfo.get_array_element())

        # recursively assign the subtypes
        for i in range(subtype_count):
            member = ida_typeinf.udt_member_t()
            member.offset = i
            tinfo.find_udt_member(member, ida_typeinf.STRMEM_INDEX)
            if not self.assign_type(member.type):
                return False
        return True


class GoCall:
    """
    This call class is intended to receive type infos for function parameters and return type
    and create the correct calling convention
    """

    correct_cc = (
        ida_typeinf.CM_CC_MANUAL
        if float(get_kernel_version()) <= 7.7
        else ida_typeinf.CM_CC_SPECIAL
    )

    def __init__(
        self, mba: ida_hexrays.mba_t, callee_ea: int, tinfo: ida_typeinf.tinfo_t = None
    ) -> None:
        self.reg_count = 0
        self.current_stack = 0
        self.max_reg = len(go_fast_convention)
        self.__args = []

        self.callinfo = ida_hexrays.mcallinfo_t()
        self.callinfo.args = ida_hexrays.mcallargs_t()
        self.callinfo.cc = self.correct_cc

        self.callinfo.spoiled = ida_hexrays.mlist_t()
        self.callinfo.return_regs = ida_hexrays.mlist_t()
        self.callinfo.callee = callee_ea
        self.mba = mba

        self.ret_type = "void *"
        self.ret_loc = "rax"
        if tinfo is not None:
            for i in range(tinfo.get_nargs()):
                self.add_arg(tinfo.get_nth_arg(i))
            self.add_ret(tinfo.get_rettype())

    def get_decl_string(self) -> str:
        """Format the function prototype from our known args and return values"""
        if self.ret_type != "void":
            return f"{self.ret_type} __usercall func@<{self.ret_loc}>({','.join(self.__args)});"
        else:
            return f"void __usercall func({','.join(self.__args)});"

    def upsert_stack_struct(self, tinfo: ida_typeinf.tinfo_t):
        gap_range = ida_range.rangeset_t()
        tinfo.calc_gaps(gap_range)
        if not gap_range.empty():
            if (
                ida_typeinf.parse_decl(
                    tinfo, None, f"{tinfo.dstr()}_nogaps;", ida_typeinf.PT_SIL
                )
                is None
            ):
                fill_tinfo(tinfo)
                ida_typeinf.parse_decl(
                    tinfo, None, f"{tinfo.dstr()}_nogaps;", ida_typeinf.PT_SIL
                )
        return tinfo

    def __create_argloc(
        self, tinfo: ida_typeinf.tinfo_t, is_return: bool
    ) -> tuple[ida_typeinf.scattered_aloc_t, str]:
        tinfo_size = tinfo.get_size()
        if tinfo_size == BADADDR:
            return

        loc_list = list()
        current_type_reg_split: str
        scattered = ida_typeinf.scattered_aloc_t()
        reg_count = self.reg_count
        if is_return:
            reg_count = 0
        # loc = ida_hexrays.vdloc_t()
        if (
            not GoTypeAssigner(loc_list).assign_type(tinfo)
            or len(loc_list) > self.max_reg - reg_count
        ):
            self.upsert_stack_struct(tinfo)
            current_type_reg_split = f"0:^{self.current_stack}.{tinfo_size}"
            argpart = ida_typeinf.argpart_t()
            argpart.set_stkoff(self.current_stack)
            argpart.off = 0
            argpart.size = tinfo_size
            scattered.push_back(argpart)
            if not is_return:
                self.current_stack += tinfo_size
        else:
            current_offset = 0
            reg_split = []

            for arg_size in loc_list:
                # when using scattered arguments from vdloc, make sure to use micro registers and not regular registers
                argpart = ida_typeinf.argpart_t()
                argpart.off = current_offset
                argpart.size = arg_size
                argpart.set_reg1(
                    ida_hexrays.reg2mreg(
                        ida_idp.str2reg(
                            get_sized_register_by_name(
                                go_fast_convention[reg_count], arg_size
                            )
                        )
                    )
                )
                scattered.push_back(argpart)

                # align offset if not aligned
                if current_offset % arg_size != 0:
                    current_offset += arg_size - (current_offset % arg_size)
                # add an arg part in the specified register
                reg_split.append(
                    f"{current_offset}:{get_sized_register_by_name(go_fast_convention[reg_count], arg_size)}"
                )

                reg_count += 1
                if not is_return:
                    self.reg_count = reg_count
                current_offset += arg_size

            current_type_reg_split = ",".join(reg_split)

        return scattered, current_type_reg_split

    def add_arg(self, tinfo: ida_typeinf.tinfo_t) -> None:
        """
        Calculate the string needed for inserting the current type to the function prototype as an argument
        """
        tinfo_copy = tinfo.copy()
        scattered, current_type_reg_split = self.__create_argloc(tinfo_copy, False)
        loc = ida_hexrays.vdloc_t()
        current_mcall = ida_hexrays.mcallarg_t()

        # convert the argloc we got into a vdloc for the mcallarg
        if len(scattered) == 1:
            first_scat = scattered[0]
            if first_scat.is_reg1():
                loc.set_reg1(first_scat.reg1())
                current_mcall.argloc.set_reg1(
                    ida_hexrays.mreg2reg(loc.reg1(), first_scat.size)
                )
            else:
                loc.set_stkoff(first_scat.stkoff())
                current_mcall.argloc = loc

        if len(scattered) > 1:
            scif = ida_hexrays.scif_t(self.mba, tinfo_copy.copy())
            scif.consume_scattered(scattered)
            current_mcall.create_from_scattered_vdloc(
                self.mba, None, tinfo_copy.copy(), scif
            )

        else:
            current_mcall.create_from_vdloc(self.mba, loc, tinfo_copy.get_size())

        current_mcall.type = tinfo_copy
        current_mcall.size = tinfo_copy.get_size()

        self.callinfo.args.push_back(current_mcall)
        self.callinfo.solid_args += 1

        # finalize the argument string
        self.__args.append(f"{tinfo_copy.dstr()}@<{current_type_reg_split}>")

    def add_ret(self, tinfo: ida_typeinf.tinfo_t) -> None:
        """
        Calculate the string needed for inserting the current type to the function prototype as the return type
        """

        tinfo_copy = tinfo.copy()
        args = self.__create_argloc(tinfo_copy, False)
        scattered = []
        if args is not None:
            scattered, self.ret_loc = args[0], args[1]

        loc = ida_hexrays.vdloc_t()

        if len(scattered) == 1:
            loc = scattered[0]

        if len(scattered) > 1:
            self.callinfo.return_argloc.consume_scattered(scattered)
        else:
            self.callinfo.return_argloc = loc

        self.ret_type = tinfo_copy.dstr()
        self.callinfo.return_type = tinfo_copy.copy()
