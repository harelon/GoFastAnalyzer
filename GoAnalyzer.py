import re
import json
import itertools
from dataclasses import dataclass
from collections import defaultdict

import ida_ua
import ida_ida
import ida_idp
import ida_gdl
import ida_nalt
import ida_name
import ida_xref
import ida_bytes
import ida_funcs
import ida_allins
import ida_idaapi
import ida_struct
import ida_hexrays
import ida_netnode
import ida_segment
import ida_segregs
import ida_typeinf
from idc import BADADDR

from DecompilerLib.UniqueGoCalls import known_functions
from DecompilerLib.GoCallinfo import GoCall, get_sized_register_by_name
from DecompilerLib.utils import (
    BYTE_SIZE,
    go_fast_convention,
    GO_SUPPORTED,
    runtime_morestack_functions,
)

go_version_regex = re.compile("go\\d\\.(\\d{1,2})(\\.\\d{1,2})?$")
concat_string_number = re.compile("runtime\\.concatstring\\d")


@dataclass
class GoString:
    pointer: int = 0
    length: int = 0


class Xmm15Optimizer(ida_hexrays.microcode_filter_t):
    """
    According to the go internal abi xmm15 stores 16 bytes of zero,
    we want to optimize the decompiler output to show 16 zeros instead of saying the value of xmm15 is undefined
    """

    xmm15_code = ida_idp.str2reg("xmm15")

    def apply(self, cdg: ida_hexrays.codegen_t) -> int:
        """
        Define moving of xmm15 into the stack as a 16 bytes zero
        as specified in the go abi
        """
        l_reg = cdg.load_effective_address(0)

        # initialize micro operands
        off = ida_hexrays.mop_t(l_reg, 8)
        sel_reg = ida_hexrays.reg2mreg(ida_segregs.R_ss)
        sel = ida_hexrays.mop_t(sel_reg, 2)
        zero = ida_hexrays.mop_t()
        zero.make_number(0, 8)

        # this puts zero at the first 8 bytes of the memory
        cdg.emit(ida_hexrays.m_stx, zero, sel, off)

        # add 8 to the offset
        offset_8 = ida_hexrays.mop_t()
        offset_8.make_number(8, 8)
        cdg.emit(ida_hexrays.m_add, offset_8, off, off)

        # put zero at the second 8 bytes of the memory
        cdg.emit(ida_hexrays.m_stx, zero, sel, off)
        return ida_hexrays.MERR_OK

    def match(self, cdg: ida_hexrays.codegen_t) -> bool:
        """check if the second operand is xmm15"""
        if cdg.insn.itype in [ida_allins.NN_movups, ida_allins.NN_movdqu]:
            return cdg.insn.Op2.reg == self.xmm15_code


class FunctionStringVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(
        self,
        cfunc: ida_hexrays.citem_t,
        func: ida_funcs.func_t,
        string_tinfo: ida_typeinf.tinfo_t,
    ) -> None:
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.func = func
        self.string_tinfo = string_tinfo
        self.string_assignments: dict[str, GoString] = defaultdict(GoString)

    def define_string(self, string_ref: int, string_size: int) -> None:
        """Define correctly a string constant"""
        # string is longer than the segment it is contained in, probably false
        if ida_segment.getseg(string_ref).size() < string_size:
            return
        # no need to define a string, the reference is to a struct already
        if ida_bytes.get_flags(string_ref) & ida_bytes.FF_STRUCT == ida_bytes.FF_STRUCT:
            return

        iterator = ida_bytes.get_bytes(string_ref, string_size)
        if iterator is None:
            return

        # if the string is not decodable don't define it
        try:
            decoded = iterator.decode("utf-8")
        except UnicodeError:
            return

        # undefine the string
        ida_bytes.del_items(string_ref, 0, string_size)
        # define the string correctly
        ida_bytes.create_strlit(string_ref, string_size, ida_nalt.STRTYPE_C)

    def instruction_stores_valid_size(
        self, insn: ida_ua.insn_t, size_reg: int
    ) -> bool | None:
        """
        Check if the instruction stores a valid size for our searched string,
        if data is stored to our wanted register not in the expected format we know it's ruined,
        if the instruction is for call, all registers are changed
        """
        # the string size is stored as a dword in the register, and for some reason its phrase is void and not imm
        if (
            insn.Op2.dtype == ida_ua.dt_dword
            and insn.Op2.phrase == ida_ua.o_void
            and insn.Op1.reg == size_reg
        ):
            return True
        # if the string is used and not for our purpose then it probably won't be used for the string size
        elif insn.Op1.reg == size_reg:
            return None
        # if we arrive at a call everything changes, we can't trust registers after it
        elif insn.get_canon_feature() & ida_idp.CF_CALL != 0:
            return None
        return False

    def instruction_stores_valid_obj(
        self, insn: ida_ua.insn_t, obj_reg: int
    ) -> bool | None:
        """
        Check if the instruction stores a valid size for our searched string,
        if data is stored to our wanted register not in the expected format we know it's ruined,
        if the instruction is for call, all registers are changed
        """
        # the string size is stored as a dword in the register, and for some reason its phrase is void and not imm
        if (
            insn.Op2.dtype == ida_ua.dt_qword
            and insn.Op2.phrase == ida_ua.o_imm
            and insn.Op1.reg == obj_reg
        ):
            return True
        # if the string is used and not for our purpose then it probably won't be used for the string size
        elif insn.Op1.reg == obj_reg:
            return None
        # if we arrive at a call everything changes, we can't trust registers after it
        elif insn.get_canon_feature() & ida_idp.CF_CALL != 0:
            return None
        return False

    def visit_insn(self, e: ida_hexrays.cinsn_t) -> int:
        if e.op != ida_hexrays.cit_block:
            return 0

        for expr in e.cblock:
            if expr.op != ida_hexrays.cit_expr:
                continue
            current_expr = expr.cexpr
            if current_expr.op != ida_hexrays.cot_asg:
                continue

            # we are referencing a member of a type
            if (
                current_expr.x.op != ida_hexrays.cot_memref
                or (
                    current_expr.x.x.op != ida_hexrays.cot_var
                    and current_expr.x.x.op != ida_hexrays.cot_memptr
                    and current_expr.x.x.op != ida_hexrays.cot_idx
                )
                or current_expr.x.x.type.compare(self.string_tinfo)
            ):
                continue

            member_ref = current_expr.x
            member_parent_ref = current_expr.x.x

            string_key = member_parent_ref.dstr()

            # get member offset check if it is the ptr or the length
            member = ida_typeinf.udt_member_t()
            member.offset = member_ref.m * BYTE_SIZE
            self.string_tinfo.find_udt_member(member, ida_typeinf.STRMEM_OFFSET)

            # skip cast
            skip_cast_y = (
                current_expr.y.x
                if current_expr.y.op == ida_hexrays.cot_cast
                else current_expr.y
            )

            should_continue = False
            # save the offset of the member to be able to restore our strings
            if member.name == "ptr":
                obj_ea = None
                skip_ref_y = (
                    skip_cast_y.x
                    if skip_cast_y.op == ida_hexrays.cot_ref
                    else skip_cast_y
                )

                if skip_ref_y.op == ida_hexrays.cot_idx:
                    e = skip_ref_y
                    while e.ea == BADADDR:
                        e = self.cfunc.find_parent_of(e)

                    # we found the parent instruction
                    suspected_string_ref_ea = e.ea
                    insn = ida_ua.insn_t()

                    result = ida_xref.get_first_dref_from(suspected_string_ref_ea)

                    # find the string size if it is mentioned before the instruction
                    # same logic as previous loop
                    prev_insn = suspected_string_ref_ea
                    # if we found the size no need to search for it again
                    while result == BADADDR:
                        prev_insn = ida_ua.decode_prev_insn(insn, prev_insn)
                        if (
                            prev_insn < self.func.start_ea
                            or prev_insn == BADADDR
                            or insn.get_canon_feature() & ida_idp.CF_CALL != 0
                        ):
                            should_continue = True
                            break
                        else:
                            result = ida_xref.get_first_dref_from(prev_insn)

                    if should_continue:
                        continue

                    obj_ea = result

                elif skip_ref_y.op == ida_hexrays.cot_obj:
                    obj_ea = skip_ref_y.obj_ea

                if obj_ea:
                    self.string_assignments[string_key].pointer = obj_ea

            elif member.name == "len":
                if skip_cast_y.op == ida_hexrays.cot_num:
                    self.string_assignments[string_key].length = skip_cast_y.n._value

        return 0

    def finalize(self):
        for go_string in self.string_assignments.values():
            if go_string.pointer != 0 and go_string.length != 0:
                self.define_string(go_string.pointer, go_string.length)

    def visit_expr(self, e: ida_hexrays.cexpr_t) -> int:
        """
        Iterate all objects in decompiler and correct the size of strings
        """
        # in the case that inside the decompiler an object's type is a string
        # we then define the string param correctly
        if e.op == ida_hexrays.cot_call:
            for item in e.a:
                orig_item: ida_hexrays.carg_t = item
                if item.op == ida_hexrays.cot_cast:
                    item = item.x
                if item.op == ida_hexrays.cot_call:
                    string_tinfo = ida_typeinf.tinfo_t()
                    ida_typeinf.parse_decl(string_tinfo, None, "string x;", 0)
                    if (
                        orig_item.formal_type.compare(string_tinfo) == 0
                        and item.a[0].op == ida_hexrays.cot_num
                        and item.a[1].op == ida_hexrays.cot_obj
                    ):
                        self.define_string(item.a[1].obj_ea, item.a[0].n._value)

        if e.op == ida_hexrays.cot_obj:
            # sometimes the actual ea of the instruction is not saved in the decompiler
            # try to find it in the parent of the item
            while e.ea == BADADDR:
                e = self.cfunc.find_parent_of(e)

            # we found the parent instruction
            suspected_string_ref_ea = e.ea
            string_size = 0

            # get the string referenced by the instruction
            insn = ida_ua.insn_t()
            # move the pointer so next instruction we parse is after the one which points to the string
            next_insn_ea = (
                ida_ua.decode_insn(insn, suspected_string_ref_ea)
                + suspected_string_ref_ea
            )

            # get the register that references the string
            reg_name = ida_idp.get_reg_name(
                insn.Op1.reg, ida_ua.get_dtype_size(ida_ua.dt_qword)
            )

            # object referenced not by a param passing register, we can't know its size
            if reg_name not in go_fast_convention:
                return 0

            string_ref = ida_xref.get_first_dref_from(suspected_string_ref_ea)
            if string_ref == BADADDR:
                # get the next reg in the fastcall, the next register where the string size will be stored
                size_reg = ida_idp.str2reg(reg_name)
                result = self.instruction_stores_valid_size(insn, size_reg)
                if not result:
                    return 0
                lookup_reg = ida_idp.str2reg(
                    go_fast_convention[go_fast_convention.index(reg_name) - 1]
                )
                string_size = insn.Op2.value
                check_reg = self.instruction_stores_valid_obj
            else:
                lookup_reg = ida_idp.str2reg(
                    go_fast_convention[go_fast_convention.index(reg_name) + 1]
                )
                check_reg = self.instruction_stores_valid_size

            found = False
            while not found:
                next_insn_ea = ida_ua.decode_insn(insn, next_insn_ea) + next_insn_ea
                # string size instruction must be in the function
                if next_insn_ea > self.func.end_ea:
                    break
                else:
                    result = check_reg(insn, lookup_reg)
                    if result is None:
                        break
                    else:
                        found = result

            # find the string size if it is mentioned before the instruction
            # same logic as previous loop
            prev_insn = suspected_string_ref_ea
            # if we found the size no need to search for it again
            while not found:
                prev_insn = ida_ua.decode_prev_insn(insn, prev_insn)
                if prev_insn < self.func.start_ea or prev_insn == BADADDR:
                    return 0
                else:
                    result = check_reg(insn, lookup_reg)
                    if result is None:
                        return 0
                    else:
                        found = result

            if string_ref == BADADDR:
                suspected_string_ref_ea = insn.ea
                string_ref = ida_xref.get_first_dref_from(suspected_string_ref_ea)
            else:
                # if the Op2 of the instruction is referencing an address it means it is not the constant length we are looking for
                if insn.Op2.addr != 0:
                    return 0
                string_size = insn.Op2.value

            # if we can't extract the string then we have a problem
            self.define_string(string_ref, string_size)

        return 0


class CallAnalysisHooks(ida_hexrays.Hexrays_Hooks):
    # 8 bit registers have different ids so we need a list of all 64 bit registers and all 8 bit registers
    valid_reg_ids = set(
        itertools.chain.from_iterable(
            [
                (
                    ida_idp.str2reg(item),
                    ida_idp.str2reg(get_sized_register_by_name(item, 1)),
                )
                for item in go_fast_convention
            ]
        )
    )

    def __init__(self, node: ida_netnode.netnode, detected_go: bool) -> None:
        super().__init__()
        self.marked_eas_set = set()
        self.marked_eas_list = list()

        self.tag_name = "x"
        self.node = node
        self.node_index = self.node.index()

        self.detected_go = detected_go

        # load previously fixed function prototypes
        blob = self.node.getblob(self.node_index, self.tag_name)
        if blob:
            decompiled_eas = json.loads(blob.decode("ascii"))
            self.marked_eas_set = set(decompiled_eas)
            self.marked_eas_list = decompiled_eas

        self.known_functions = known_functions

    def save_eas(self) -> None:
        self.node.setblob(
            json.dumps(self.marked_eas_list).encode("ascii"),
            self.node_index,
            self.tag_name,
        )

    def guess_func_return_type(self, ea: int) -> str:
        used_reg = -1
        func = ida_funcs.get_func(ea)
        flow_chart = ida_gdl.qflow_chart_t("", func, func.start_ea, func.end_ea, 0)
        while flow_chart is not None:
            should_continue = False
            insn = ida_ua.insn_t()
            funcs = set()
            for i in range(flow_chart.node_qty()):

                # iterate blocks that return from the function they might contain the result registers
                if flow_chart.is_ret_block(i):

                    # skip the stack extension block, it is considered as a return block for some reason
                    current_ea = flow_chart[i].end_ea
                    if ida_xref.get_first_cref_from(current_ea) == func.start_ea:
                        continue

                    # iterate from the return backwards until we find a call which spoils all registers
                    while (
                        current_ea > flow_chart[i].start_ea
                        and not insn.get_canon_feature() & ida_idp.CF_CALL
                    ):
                        current_ea = ida_ua.decode_prev_insn(insn, current_ea)

                        # if the register we currently change is a return register we check it
                        if (
                            insn.Op1.type == ida_ua.o_reg
                            and insn.Op1.reg in self.valid_reg_ids
                        ):
                            # each time we take the max register which is changed, we can assume the function
                            # wouldn't change it if it wasn't part of its result
                            used_reg = max(
                                used_reg,
                                go_fast_convention.index(
                                    ida_idp.get_reg_name(insn.Op1.reg, 8)
                                ),
                            )

                    # gather all call instructions which are called before returning from the function
                    if insn.get_canon_feature() & ida_idp.CF_CALL:
                        funcs.add(insn.ea)

            # the function might return the result of its last called function
            if used_reg == -1:

                # check our gathered calls for their prototypes
                for ea in funcs:
                    # get the callee ea
                    xrefed_func = ida_xref.get_first_cref_from(ea)
                    while func.start_ea <= xrefed_func <= func.end_ea:
                        xrefed_func = ida_xref.get_next_cref_from(ea, xrefed_func)

                    # ignore calls to registers, we can't follow those
                    if xrefed_func == BADADDR:
                        continue

                    func = ida_funcs.get_func(xrefed_func)
                    # the called function is already defined, take its return type
                    if ida_nalt.get_aflags(xrefed_func) & ida_nalt.AFL_USERTI:
                        tinfo = ida_typeinf.tinfo_t()
                        ida_hexrays.get_type(
                            xrefed_func, tinfo, ida_hexrays.GUESSED_FUNC
                        )
                        func_details = ida_typeinf.func_type_data_t()
                        tinfo.get_func_details(func_details)
                        return func_details.rettype.dstr()
                    # recurse the inner function and try to find its return registers
                    else:
                        flow_chart = ida_gdl.qflow_chart_t(
                            "", func, func.start_ea, func.end_ea, 0
                        )
                        should_continue = True
                        break

            if should_continue:
                continue
            flow_chart = None

        # we couldn't find any registers used in the return blocks
        if used_reg == -1:
            return "void"
        elif used_reg == 0:
            return "void *"
        else:
            # sometimes functions' parents create their return type for them
            struc_name = f"retval_{func.start_ea:X}"
            if ida_struct.get_struc_id(struc_name) == BADADDR:
                # create the result struct if it doesn't exist
                retval_struc = ida_struct.add_struc(BADADDR, struc_name)
                for i in range(used_reg + 1):
                    ida_struct.add_struc_member(
                        ida_struct.get_struc(retval_struc),
                        f"part_{i}",
                        BADADDR,
                        ida_bytes.qword_flag(),
                        None,
                        8,
                    )
            return struc_name

    def fix_call_by_ea(self, mba: ida_hexrays.mba_t, callee_ea: int) -> None:
        # check if we already fixed the call
        if callee_ea in self.marked_eas_set:
            return

        # mark call as fixed one
        self.marked_eas_set.add(callee_ea)
        self.marked_eas_list.append(callee_ea)

        # save the current information
        self.save_eas()

        if ida_name.get_name(callee_ea) in runtime_morestack_functions:
            func_declaration = "void func();"

        # if the name of the function is runtime.concatstring{number} we know its prototype
        elif concat_string_number.match(ida_funcs.get_func_name(callee_ea)):

            string_count = int(ida_funcs.get_func_name(callee_ea)[-1:])

            string_concat_declaration = f"string (*)(void * tmpbuf, {', '.join([f'string a{d}' for d in range(string_count)])});"

            string_concat_tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(
                string_concat_tinfo, None, string_concat_declaration, 0
            )

            # calculate calling convention by the string concatenation count
            func_declaration = GoCall(
                mba, callee_ea, string_concat_tinfo, False
            ).get_decl_string()

        # check if the prototype of the function is already known by ida
        elif ida_nalt.get_aflags(callee_ea) & ida_nalt.AFL_USERTI:
            tinfo = ida_typeinf.tinfo_t()
            ida_hexrays.get_type(callee_ea, tinfo, ida_hexrays.GUESSED_FUNC)
            func_declaration = GoCall(
                mba, callee_ea, tinfo, self.detected_go
            ).get_decl_string()

        # we can only guess the calling convention manually by the assembly
        else:
            func = ida_funcs.get_func(callee_ea)
            end_ea = func.end_ea
            current_ea = func.start_ea

            # find the first jump
            next_ea = ida_bytes.next_head(current_ea, end_ea)
            while ida_xref.get_next_cref_from(current_ea, next_ea) == BADADDR:
                current_ea = next_ea
                next_ea = ida_bytes.next_head(current_ea, end_ea)
                if current_ea == BADADDR:
                    return

            # start iterating the stack extension block
            insn = ida_ua.insn_t()
            current_insn_ea = current_ea + ida_ua.decode_insn(insn, current_ea)
            current_insn_ea = ida_xref.get_next_cref_from(current_ea, current_insn_ea)

            # if the first instruction in the block is not one of storing registers than it means we are not in a go fastcall
            current_insn_ea = current_insn_ea + ida_ua.decode_insn(
                insn, current_insn_ea
            )
            if (
                insn.Op1.type != ida_ua.o_displ
                or insn.Op1.addr == 0
                or insn.Op2.reg not in self.valid_reg_ids
            ):
                xrefed_func = ida_xref.get_first_cref_from(insn.ea)
                while func.start_ea <= xrefed_func <= func.end_ea:
                    xrefed_func = ida_xref.get_next_cref_from(insn.ea, xrefed_func)
                if ida_name.get_name(xrefed_func) not in runtime_morestack_functions:
                    return

            func_declaration = ""

            param_regs_list = []
            # iterate until the stack extension call
            while insn.get_canon_feature() & ida_idp.CF_CALL == 0:
                # extract stored register into func declaration
                if insn.Op1.type == ida_ua.o_displ and insn.Op1.addr != 0:
                    op2_dtype_size = ida_ua.get_dtype_size(insn.Op2.dtype)
                    param_regs_list.append(f"__int{op2_dtype_size * BYTE_SIZE}")
                    if not self.detected_go:
                        param_regs_list[
                            -1
                        ] += f"@<{ida_idp.get_reg_name(insn.Op2.reg, op2_dtype_size)}>"
                current_insn_ea = current_insn_ea + ida_ua.decode_insn(
                    insn, current_insn_ea
                )

            # finalize func declaration
            func_declaration = self.guess_func_return_type(callee_ea)
            if not self.detected_go:
                if func_declaration != "void":
                    call = GoCall(None, 0, detected_go=self.detected_go)
                    call_ret = ida_typeinf.tinfo_t()
                    ida_typeinf.parse_decl(call_ret, None, f"{func_declaration};", 0)
                    call.add_ret(call_ret)
                    func_declaration = (
                        f"{call.ret_type} __usercall func@<{call.ret_loc}>"
                    )
                else:
                    func_declaration = f"void __usercall func"
            else:
                func_declaration = f"{func_declaration} __golang func"
            func_declaration += f"({','.join(param_regs_list)});"

        # set function typeinfo
        call_info = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(call_info, None, func_declaration, 0)
        ida_typeinf.apply_tinfo(callee_ea, call_info, ida_typeinf.TINFO_DEFINITE)

    # fix the current call information
    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int) -> int:
        if new_maturity == ida_hexrays.CMAT_FINAL:
            self.fix_call_by_ea(cfunc.mba, cfunc.entry_ea)
            # fix strings in decompiler
            func = ida_funcs.get_func(cfunc.entry_ea)
            tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tinfo, None, "string;", ida_typeinf.PT_SIL)
            function_string_visitor = FunctionStringVisitor(cfunc.body, func, tinfo)
            function_string_visitor.apply_to(cfunc.body, None)
            function_string_visitor.finalize()
        return 0

    def build_callinfo(
        self, blk: ida_hexrays.mblock_t, call_type: ida_typeinf.tinfo_t
    ) -> ida_hexrays.mcallinfo_t | None:
        """
        Fix the calls our decompiled function calls to, resulting in a satisfying decompilation
        Also fix casts of known functions
        """
        call_insn = blk.tail

        # in the hexrays microcode the callee is at the left operand
        # we check here that the type of call is global, which means it is a call to a specific function
        # and not to an interface
        if call_insn.l.t == ida_hexrays.mop_v:
            callee_ea = call_insn.l.g
            func_name = ida_funcs.get_func_name(callee_ea)
            if func_name in self.known_functions.keys():
                return self.known_functions[func_name].get_decl_mi(
                    blk.mba, call_insn.ea, callee_ea
                )
            self.fix_call_by_ea(blk.mba, callee_ea)


class R14Optimizer(ida_hexrays.optinsn_t):

    def __init__(self) -> None:
        super().__init__()
        self.r14_code = ida_hexrays.reg2mreg(ida_idp.str2reg("r14"))

    def func(
        self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t, optflags: int
    ) -> int:
        """
        Find uses of r14 in the microcode, replace them with calls to an helper named CurrentGoroutine
        This helper is meant to mimic how ida converts fs/gs access to the NtCurrentTeb helper
        """
        current_insn = blk.head

        while current_insn != blk.tail and current_insn is not None:
            left_op = current_insn.l
            if (
                current_insn.opcode == ida_hexrays.m_mov
                and left_op.t == ida_hexrays.mop_r
                and left_op.r == self.r14_code
            ):
                # take the operand and the type from the original micro instruction
                call_insn = ida_hexrays.minsn_t(current_insn.ea)
                call_insn.opcode = ida_hexrays.m_call

                # initialize the helper part
                helper_mop = ida_hexrays.mop_t()
                helper_mop.make_helper("CurrentGoroutine")
                call_insn.l = helper_mop

                # initialize the callinfo part
                callinfo_mop = ida_hexrays.mop_t()
                callinfo = ida_hexrays.mcallinfo_t()

                # set the return type to be the runtime_g (the goroutine struct)
                return_type = ida_typeinf.tinfo_t()
                ida_typeinf.parse_decl(return_type, None, "runtime_g * x;", 0)

                # set function return regs
                regs_vec = ida_hexrays.mopvec_t()
                return_mop = ida_hexrays.mop_t()
                return_mop.make_reg(current_insn.d.r, 8)
                regs_vec.push_back(return_mop)

                # set the function return locations
                regs_list = ida_hexrays.mlist_t()
                regs_list.add(current_insn.d.r, 8)

                # set the location of the returned value
                ret_loc = ida_typeinf.argloc_t()
                ret_loc.set_reg1(current_insn.d.r)

                # set the registers spoiled by this function
                spoiled_list = ida_hexrays.mlist_t()
                spoiled_list.add(current_insn.d.r, 8)

                # set all of the callinfo information
                callinfo.return_type = return_type
                callinfo.retregs = regs_vec
                callinfo.return_regs = regs_list
                callinfo.spoiled = spoiled_list
                callinfo.return_argloc = ret_loc
                callinfo.flags = ida_hexrays.FCI_NOSIDE
                callinfo.cc = ida_typeinf.CM_CC_FASTCALL

                # set the actual micro instruction
                callinfo_mop.t = ida_hexrays.mop_f
                callinfo_mop.f = callinfo
                callinfo_mop.size = 8
                call_insn.d = callinfo_mop

                # put the call to the helper as an operand
                blk.insert_into_block(call_insn, current_insn.prev)
                blk.make_nop(current_insn)
            current_insn = current_insn.next

        return 0


class GoAnalyzer(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    wanted_name = "GoAnalyzer"
    GOANALYZER_NODE = "GoAnalyzerNode"

    def init(self) -> int:
        self.enabled = False
        self.initialized = False

        if not ida_hexrays.init_hexrays_plugin():
            return ida_idaapi.PLUGIN_SKIP

        # only 64 bit go has the abi we fix
        if not ida_ida.inf_is_64bit() or ida_idp.ph_get_id() != ida_idp.PLFM_386:
            return ida_idaapi.PLUGIN_SKIP

        # go version is specified in the data/go.buildinfo sections, check it
        data_segment: ida_segment.segment_t
        if ida_ida.inf_get_filetype() == ida_ida.f_PE:
            data_segment = ida_segment.get_segm_by_name(".data")
        elif ida_ida.inf_get_filetype() == ida_ida.f_ELF:
            data_segment = ida_segment.get_segm_by_name(".go.buildinfo")
        else:
            return ida_idaapi.PLUGIN_SKIP

        # if there is no data segment means it can't be in go
        if data_segment is None:
            return ida_idaapi.PLUGIN_SKIP

        # check the data segment if the version string length is reasonable
        VERSION_STRING_OFFSET = 0x20
        seg_start = data_segment.start_ea
        version_string_len = ida_bytes.get_db_byte(seg_start + VERSION_STRING_OFFSET)
        if (
            version_string_len is None
            or version_string_len > 15
            or version_string_len < 5
        ):
            return ida_idaapi.PLUGIN_SKIP

        # we probably have the go version string
        supposed_version_string = ida_bytes.get_bytes(
            seg_start + VERSION_STRING_OFFSET + 1, version_string_len
        ).decode("ascii")
        # if it is unknown allow manual activation
        if "unknown" in supposed_version_string.lower():
            print("Didn't detect go version, try manually in the plugins menu")
            return ida_idaapi.PLUGIN_KEEP

        match = go_version_regex.match(supposed_version_string)
        MINIMAL_REGISTER_ABI_GO_VERSION = 17
        # check if the go version is higher than 1.17 which means that the register abi is on
        if not match or int(match.group(1)) < MINIMAL_REGISTER_ABI_GO_VERSION:
            return ida_idaapi.PLUGIN_SKIP

        print(f"Detected {supposed_version_string}")
        self.run(None)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _) -> int:
        """Install all the hooks we need and do our initialization"""
        if not self.initialized:
            self.detected_go = False
            if (
                GO_SUPPORTED
                and ida_idaapi.get_inf_structure().cc.cm & ida_typeinf.CM_CC_MASK
                == ida_typeinf.CM_CC_GOLANG
            ):
                self.detected_go = True

            # initialize our netnode, we don't want to recompile everything all the time
            self.node = ida_netnode.netnode()
            self.node.create(GoAnalyzer.GOANALYZER_NODE)

            self.hooks = CallAnalysisHooks(self.node, self.detected_go)
            self.filter = Xmm15Optimizer()
            self.optimizer = R14Optimizer()

            # create the goroutine struct if it doesn't already exist
            if (
                ida_typeinf.get_named_type(None, "runtime_g", ida_typeinf.NTF_TYPE)
                is None
            ):
                ida_struct.add_struc(BADADDR, "runtime_g")

            # create the string struct if it doesn't already exist
            if ida_typeinf.get_named_type(None, "string", ida_typeinf.NTF_TYPE) is None:
                string_struc = ida_struct.add_struc(BADADDR, "string")
                ida_struct.add_struc_member(
                    ida_struct.get_struc(string_struc),
                    "ptr",
                    BADADDR,
                    ida_bytes.qword_flag(),
                    None,
                    8,
                )
                ida_struct.add_struc_member(
                    ida_struct.get_struc(string_struc),
                    "len",
                    BADADDR,
                    ida_bytes.qword_flag(),
                    None,
                    8,
                )

            self.initialized = True
            print("GoAnalyzer Initialized")

        if not self.enabled:
            self.hooks.hook()

            # install the xmm15 zero operand optimizer
            ida_hexrays.install_microcode_filter(self.filter, True)

            # install the r14 current goroutine optimizer
            self.optimizer.install()
            self.enabled = True
            print("GoAnalyzer Enabled")
        else:
            self.hooks.unhook()

            # uninstall the xmm15 zero operand optimizer
            ida_hexrays.install_microcode_filter(self.filter, False)

            # uninstall the r14 current goroutine optimizer
            self.optimizer.remove()

            self.enabled = False
            print("GoAnalyzer Disabled")
        return 0

    def term(self) -> None:
        pass


def PLUGIN_ENTRY() -> GoAnalyzer:
    return GoAnalyzer()
