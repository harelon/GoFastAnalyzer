import re
import json
import itertools

import ida_ua
import ida_ida
import ida_idp
import ida_nalt
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
from DecompilerLib.utils import BYTE_SIZE, go_fast_convention
from DecompilerLib.GoCallinfo import GoCall, get_sized_register_by_name

go_version_regex = re.compile("go\\d\\.(\\d{1,2})(\\.\\d{1,2})?$")
concat_string_number = re.compile("runtime\\.concatstring\\d")


data_sizes_map = {
    ida_ua.dt_byte16: 16,
    ida_ua.dt_qword: 8,
    ida_ua.dt_dword: 4,
    ida_ua.dt_word: 2,
    ida_ua.dt_byte: 1,
}


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
    def __init__(self, cfunc: ida_hexrays.citem_t, func: ida_funcs.func_t):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.func = func

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

            # if the suspected ea has no drefs we can't assume it is not referencing a string
            string_ref = ida_xref.get_first_dref_from(suspected_string_ref_ea)
            if string_ref == BADADDR:
                return 0

            # get the string referenced by the instruction
            insn = ida_ua.insn_t()
            # move the pointer so next instruction we parse is after the one which points to the string
            next_insn_ea = (
                ida_ua.decode_insn(insn, suspected_string_ref_ea)
                + suspected_string_ref_ea
            )

            # get the register that references the string
            ptr_reg = insn.Op1.reg
            reg_name = ida_idp.get_reg_name(ptr_reg, data_sizes_map[insn.Op1.dtype])

            # if the pointer is in the last register it can't be a string because of how go strings work
            if reg_name not in go_fast_convention[:-1]:
                return 0

            # get the next reg in the fastcall, the next register where the string size will be stored
            size_reg = ida_idp.str2reg(
                go_fast_convention[go_fast_convention.index(reg_name) + 1]
            )

            found = False
            while not found:
                next_insn_ea = ida_ua.decode_insn(insn, next_insn_ea) + next_insn_ea
                # string size instruction must be in the function
                if next_insn_ea > self.func.end_ea:
                    break
                else:
                    result = self.instruction_stores_valid_size(insn, size_reg)
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
                    result = self.instruction_stores_valid_size(insn, size_reg)
                    if result is None:
                        return 0
                    else:
                        found = result

            # if the Op2 of the instruction is referencing an address it means it is not the constant length we are looking for
            if insn.Op2.addr != 0:
                return 0

            # if we can't extract the string then we have a problem
            self.define_string(string_ref, insn.Op2.value)
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

    def __init__(self, node: ida_netnode.netnode):
        super().__init__()
        self.marked_eas_set = set()
        self.marked_eas_list = list()

        self.tag_name = "x"
        self.node = node
        self.node_index = self.node.index()

        # load previously fixed function prototypes
        blob = self.node.getblob(self.node_index, self.tag_name)
        if blob:
            decompiled_eas = json.loads(blob.decode("ascii"))
            self.marked_eas_set = set(decompiled_eas)
            self.marked_eas_list = decompiled_eas

        self.known_functions = known_functions

    def save_eas(self):
        self.node.setblob(
            json.dumps(self.marked_eas_list).encode("ascii"),
            self.node_index,
            self.tag_name,
        )

    def fix_call_by_ea(self, mba, callee_ea) -> None:
        # check if we already fixed the call
        if callee_ea in self.marked_eas_set:
            return

        # mark call as fixed one
        self.marked_eas_set.add(callee_ea)
        self.marked_eas_list.append(callee_ea)

        # save the current information
        self.save_eas()

        # check if the prototype of the function is already known by ida
        if ida_nalt.get_aflags(callee_ea) & ida_nalt.AFL_USERTI:
            tinfo = ida_typeinf.tinfo_t()
            ida_hexrays.get_type(callee_ea, tinfo, ida_hexrays.GUESSED_FUNC)
            call = GoCall(mba, callee_ea, tinfo)
            func_declaration = call.get_decl_string()

        # if the name of the function is runtime.concatstring{number} we know its prototype
        elif concat_string_number.match(ida_funcs.get_func_name(callee_ea)):

            string_count = int(ida_funcs.get_func_name(callee_ea)[-1:])

            string_tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(string_tinfo, None, "string x;", 0)

            tmpbuf_tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tmpbuf_tinfo, None, "void *x;", 0)

            # calculate calling convention by the string concatenation count
            call = GoCall(mba, callee_ea)
            call.add_arg(tmpbuf_tinfo)
            for _ in range(string_count):
                call.add_arg(string_tinfo)
            call.add_ret(string_tinfo)
            func_declaration = call.get_decl_string()

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
                return

            func_declaration = ""

            param_regs_list = []
            # iterate until the stack extension call
            while insn.get_canon_feature() & ida_idp.CF_CALL == 0:
                # extract stored register into func declaration
                if insn.Op1.type == ida_ua.o_displ and insn.Op1.addr != 0:
                    param_regs_list.append(
                        f"__int{data_sizes_map[insn.Op2.dtype]*BYTE_SIZE}@<{ida_idp.get_reg_name(insn.Op2.reg, data_sizes_map[insn.Op2.dtype])}>"
                    )
                current_insn_ea = current_insn_ea + ida_ua.decode_insn(
                    insn, current_insn_ea
                )

            # finalize func declaration
            func_declaration = (
                f"void * __usercall func@<rax>({','.join(param_regs_list)});"
            )
        # set function typeinfo
        call_info = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(call_info, None, func_declaration, 0)
        ida_typeinf.apply_tinfo(callee_ea, call_info, ida_typeinf.TINFO_DEFINITE)

    # fix the current call information
    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity):
        if new_maturity == ida_hexrays.CMAT_FINAL:
            self.fix_call_by_ea(cfunc.mba, cfunc.entry_ea)
            # fix strings in decompiler
            func = ida_funcs.get_func(cfunc.entry_ea)
            function_string_visitor = FunctionStringVisitor(cfunc.body, func)
            function_string_visitor.apply_to(cfunc.body, None)
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

    def __init__(self):
        super().__init__()
        self.r14_code = ida_hexrays.reg2mreg(ida_idp.str2reg("r14"))

    def func(self, blk: ida_hexrays.mblock_t, ins, optflags):
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

    def init(self):
        # do it by finding the last reference to the UNCOMMON_TYPE_METHOD type
        # fix_strings()
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

    def run(self, _):
        """Install all the hooks we need and do our initialization"""
        if not self.initialized:
            # initialize our netnode, we don't want to recompile everything all the time
            self.node = ida_netnode.netnode()
            self.node.create(GoAnalyzer.GOANALYZER_NODE)

            self.hooks = CallAnalysisHooks(self.node)
            self.filter = Xmm15Optimizer()
            self.optimizer = R14Optimizer()

            # create the goroutine struct if it doesn't already exist
            if (
                ida_typeinf.get_named_type(None, "runtime_g", ida_typeinf.NTF_TYPE)
                is None
            ):
                ida_struct.add_struc(BADADDR, "runtime_g")

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

    def term(self):
        pass


def PLUGIN_ENTRY():
    return GoAnalyzer()
