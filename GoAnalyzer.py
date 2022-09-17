import re
import json
import string

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

go_version_regex = re.compile("go\\d\\.(\\d{1,2})(\\.\\d{1,2})?$")

# get the index of the register that stores the string size, by the register containing the pointer
following_reg = {
    0: 3,
    3: 1,
    1: 7,
    7: 6,
    6: 8,
    8: 9,
    9: 10,
    10: 11
}

# get usercall argument location by size and reg
go_fast_convention = {
    0: {
        7: "__int64@<rax>",
        2: "__int32@<eax>",
        1: "__int16@<ax>"
    },
    16: {
        0: "__int8@<al>"
    },
    3: {
        7: "__int64@<rbx>",
        2: "__int32@<ebx>",
        1: "__int16@<bx>"
    },
    19: {
        0: "__int8@<bl>"
    },
    1: {
        7: "__int64@<rcx>",
        2: "__int32@<ecx>",
        1: "__int16@<cx>"
    },
    17: {
        0: "__int8@<cl>"
    },
    7: {
        7: "__int64@<rdi>",
        2: "__int32@<edi>",
        1: "__int16@<di>"
    },
    27: {
        0: "__int8@<dil>"
    },
    6: {
        7: "__int64@<rsi>",
        2: "__int32@<esi>",
        1: "__int16@<si>"
    },
    26: {
        0: "__int8@<sil>"
    },
    8: {
        7: "__int64@<r8>",
        2: "__int32@<r8d>",
        1: "__int16@<r8w>",
        0: "__int8@<r8b>"
    },
    9: {
        7: "__int64@<r9>",
        2: "__int32@<r9d>",
        1: "__int16@<r9w>",
        0: "__int8@<r9b>"
    },
    10: {
        7: "__int64@<r10>",
        2: "__int32@<r10d>",
        1: "__int16@<r10w>",
        0: "__int8@<r10b>"
    },
    11: {
        7: "__int64@<r11>",
        2: "__int32@<r11d>",
        1: "__int16@<r11w>",
        0: "__int8@<r11b>"
    },
    64: {
        8: "__int128@<xmm0>"
    },
    65: {
        8: "__int128@<xmm1>"
    },
    66: {
        8: "__int128@<xmm2>"
    },
}


class Xmm15Optimizer(ida_hexrays.microcode_filter_t):
    xmm15_code = 0x4f

    # define moving of xmm15 into the stack as a 16 bytes zero
    # as specified in the go abi
    def apply(self, cdg: ida_hexrays.codegen_t):
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

    def match(self, cdg: ida_hexrays.codegen_t):
        if cdg.insn.itype == ida_allins.NN_movups or cdg.insn.itype == ida_allins.NN_movdqu:
            # check if the second operand is xmm15
            return cdg.insn.Op2.reg == self.xmm15_code


class GoTypeAssigner():
    def __init__(self, arg_sizes: list):
        self.arg_sizes = arg_sizes

    # Assign the type into registers or stack
    def assign_type(self, tif: ida_typeinf.tinfo_t):

        if tif.get_size() == 0:
            return True

        subtype_count = tif.get_udt_nmembers()
        # the type is atomic
        if subtype_count == -1:
            if tif.is_decl_bool() or tif.is_scalar() or tif.is_ptr():
                self.arg_sizes.append(tif.get_size())
                return True

            # arrays of 2 and more make the type passed on the stack
            if tif.is_decl_array() and tif.get_array_nelems() > 1:
                self.arg_sizes.clear()
                return False

            return True

        # recursively assign the subtypes
        for i in range(subtype_count):
            member = ida_typeinf.udt_member_t()
            member.offset = i
            tif.find_udt_member(member, ida_typeinf.STRMEM_INDEX)
            if not self.assign_type(member.type):
                return False
        return True


class GoCall:
    """
    This call class is intended to recieve type infos for function parameters and return type
    and create the correct calling convetion
    """
    def __init__(self):
        self.reg_count = 0
        self.current_stack = 0
        self.register_args = [
            {8: "rax", 4: "eax", 2: "ax", 1: "al"},
            {8: "rbx", 4: "ebx", 2: "bx", 1: "bl"},
            {8: "rcx", 4: "ecx", 2: "cx", 1: "cl"},
            {8: "rdi", 4: "edi", 2: "di", 1: "dil"},
            {8: "rsi", 4: "esi", 2: "si", 1: "sil"},
            {8: "r8", 4: "r8d", 2: "r8w", 1: "r8b"},
            {8: "r9", 4: "r9d", 2: "r9w", 1: "r9b"},
            {8: "r10", 4: "r10d", 2: "r10w", 1: "r10b"},
            {8: "r11", 4: "r11d", 2: "r11w", 1: "r11b"}
        ]
        self.max_reg = len(self.register_args)
        self._args_string = ""
        self.reg_size = 8

        self.ret_type = "void"
        self.ret_loc = ""

    # format the function prototype from our known args and return values
    def get_decl_string(self):
        return f"{self.ret_type} __usercall func{self.ret_loc}({self._args_string[:-1]});"

    def add_arg(self, tinfo: ida_typeinf.tinfo_t):
        tinfo_size = tinfo.get_size()
        if tinfo_size <= 0:
            return
        self._args_string = f"{self._args_string} {tinfo.dstr()}@<"

        loc_list = list()

        addend = ""
        # if we failed in register assigning, fallback to stack assignment
        if not GoTypeAssigner(loc_list).assign_type(tinfo) or len(loc_list) > self.max_reg - self.reg_count:
            addend = f"0:^{self.current_stack}.{tinfo_size}"
            self.current_stack += tinfo_size
        else:
            current_offset = 0
            for arg_size in loc_list:
                if current_offset % arg_size != 0:
                    current_offset += arg_size - (current_offset % arg_size)
                addend = f"{addend}{current_offset}:{self.register_args[self.reg_count][arg_size]},"
                self.reg_count += 1
                current_offset += arg_size
            addend = addend[:-1]

        self._args_string = f"{self._args_string}{addend}>,"

    # set function return type
    def add_ret(self, tinfo: ida_typeinf.tinfo_t):
        tinfo_size = tinfo.get_size()
        if tinfo_size == 0 or tinfo_size == BADADDR:
            return

        loc_list = list()

        ret_loc = "@<"
        # if we failed in register assigning, fallback to stack assignment
        if not GoTypeAssigner(loc_list).assign_type(tinfo) or len(loc_list) > self.max_reg:
            ret_loc = f"{ret_loc}0:^{self.current_stack}.{tinfo_size}"
        # put aligned struct members in registers
        else:
            reg_count = 0
            current_offset = 0
            for arg_size in loc_list:
                if current_offset % arg_size != 0:
                    current_offset += arg_size - (current_offset % arg_size)
                ret_loc = f"{ret_loc}{current_offset}:{self.register_args[reg_count][arg_size]},"
                reg_count += 1
                current_offset += arg_size
            ret_loc = ret_loc[:-1]

        self.ret_type = tinfo.dstr()
        self.ret_loc = f"{ret_loc}>"


class FunctionStringVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc: ida_hexrays.citem_t, func):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.func = func

    # iterate all objects in decompiler and correct the size of strings
    def visit_expr(self, e: ida_hexrays.cexpr_t):
        if e.op == ida_hexrays.cot_obj:
            # sometimes the actual ea of the instruction is not saved in the decompiler
            # try to find it in the parent of the item
            while e.ea == BADADDR:
                e = self.cfunc.find_parent_of(e)

            # we found the parent instruction
            suspected_string_ref_ea = e.ea

            # get the string refrenced by the instruction
            insn = ida_ua.insn_t()
            next_insn = ida_ua.decode_insn(insn, suspected_string_ref_ea) + suspected_string_ref_ea
            string_ref = ida_xref.get_first_dref_from(suspected_string_ref_ea)
            if string_ref == BADADDR:
                return 0

            # get the register that references the string
            ptr_reg = insn.Op1.reg
            if ptr_reg not in following_reg.keys():
                return 0
            # get the next reg in the fastcall, the next register where the string size will be stored
            size_reg = following_reg[ptr_reg]

            # find the string size if it is mentioned after the instruction
            next_insn = ida_ua.decode_insn(insn, next_insn) + next_insn
            found = False
            while True:
                # string size instruction must be in the function
                if next_insn >= self.func.end_ea:
                    break
                # the string size is stored as a dword in the register, and for some reason its phrase is void and not imm
                elif insn.Op2.dtype == ida_ua.dt_dword and insn.Op2.phrase == ida_ua.o_void and insn.Op1.reg == size_reg:
                    found = True
                    break
                # if the string is used and not for our purpose then it probably won't be used for it
                elif insn.Op1.reg == size_reg:
                    break
                # if we arrive at a call everything changes, we can't trust registers after it
                elif insn.get_canon_feature() & ida_idp.CF_CALL != 0:
                    break
                next_insn = ida_ua.decode_insn(insn, next_insn) + next_insn

            # find the string size if it is mentioned before the instruction
            # same logic as previous loop
            prev_insn = suspected_string_ref_ea
            # if we found the size no need to search for it again
            while not found:
                prev_insn = ida_ua.decode_prev_insn(insn, prev_insn)
                if prev_insn < self.func.start_ea:
                    return 0
                elif insn.Op2.dtype == ida_ua.dt_dword and insn.Op2.phrase == ida_ua.o_void and insn.Op1.reg == size_reg:
                    break
                elif insn.Op1.reg == size_reg:
                    return 0
                elif insn.get_canon_feature() & ida_idp.CF_CALL != 0:
                    return 0

            if insn.Op2.addr != 0:
                return 0
            # if we can't extract the string then we have a problem
            string_size = insn.Op2.value
            iterator = ida_bytes.get_bytes(string_ref, string_size)
            if iterator is None:
                return 0

            # if there are non printable characters in the string it means we are probably wrong
            if not all(chr(i) in string.printable for i in iterator):
                return 0
            # undefine the string
            ida_bytes.del_items(string_ref, 0, string_size)
            # define the string correctly
            ida_bytes.create_strlit(string_ref, string_size, ida_nalt.STRTYPE_C)

        return 0


class CallAnalysisHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self, node):
        super().__init__()
        self.marked_eas_set = set()
        self.marked_eas_list = list()
        self.tag_name = 'x'
        self.node = node
        self.node_index = self.node.index()
        # load previously fixed function prototypes
        blob = self.node.getblob(self.node_index, self.tag_name)
        if blob:
            jsons = json.loads(blob.decode("ascii"))
            self.marked_eas_set = set(jsons)
            self.marked_eas_list = jsons

    def fix_call_by_ea(self, ea):
        # check if we already fixed the call
        if ea in self.marked_eas_set:
            return

        # mark call as fixed one
        self.marked_eas_set.add(ea)
        self.marked_eas_list.append(ea)
        self.node.setblob(json.dumps(self.marked_eas_list).encode("ascii"), self.node_index, self.tag_name)

        # check if the prototype of the function is already known by ida
        if ida_nalt.get_aflags(ea) & ida_nalt.AFL_USERTI:
            tinfo = ida_typeinf.tinfo_t()
            ida_hexrays.get_type(ea, tinfo, ida_hexrays.GUESSED_FUNC)
            call = GoCall()
            for i in range(tinfo.get_nargs()):
                call.add_arg(tinfo.get_nth_arg(i))
            call.add_ret(tinfo.get_rettype())
            func_declaration = call.get_decl_string()
        # we can only guess the calling convention manually by the assembly
        else:
            func = ida_funcs.get_func(ea)
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

            # if the first instruction in the block is not one of storing registers than it means we are not in a gofast call
            current_insn_ea = current_insn_ea + ida_ua.decode_insn(insn, current_insn_ea)
            if insn.Op1.type != ida_ua.o_displ or insn.Op1.addr == 0 or insn.Op2.reg not in go_fast_convention.keys():
                return

            func_declaration = "void * __usercall func@<rax>("

            # iterate until the stack extension call
            while insn.get_canon_feature() & ida_idp.CF_CALL == 0:
                # extract stored register into func decleration
                if insn.Op1.type == ida_ua.o_displ and insn.Op1.addr != 0:
                    func_declaration = f"{func_declaration}{go_fast_convention[insn.Op2.reg][insn.Op2.dtype]}, "
                current_insn_ea = current_insn_ea + ida_ua.decode_insn(insn, current_insn_ea)

            # finalize func declaration
            func_declaration = func_declaration.rstrip(", ")
            func_declaration = f"{func_declaration});"

        # set function typeinfo
        call_info = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(call_info, None, func_declaration, 0)
        ida_typeinf.apply_tinfo(
            ea,
            call_info,
            ida_typeinf.TINFO_DEFINITE
        )

    # fix the current call information
    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturiy):
        if new_maturiy == ida_hexrays.CMAT_FINAL:
            self.fix_call_by_ea(cfunc.entry_ea)
            # fix strings in decompiler
            func = ida_funcs.get_func(cfunc.entry_ea)
            function_string_visitor = FunctionStringVisitor(cfunc.body, func)
            function_string_visitor.apply_to(cfunc.body, None)
        return 0

    # fix the calls our decompiled function calls to, resulting in a satisfyind decompilation
    def build_callinfo(self, blk: ida_hexrays.mblock_t, call_type: ida_typeinf.tinfo_t):
        call_insn = blk.tail
        # in the hexrays microcode the callee is at the left operand
        # we check here that the type of call is global, which means it is a call to a specific function
        # and not to an interface
        if call_insn.l.t == ida_hexrays.mop_v:
            callee_ea = call_insn.l.g
            self.fix_call_by_ea(callee_ea)


class R14Optimizer(ida_hexrays.optinsn_t):
    r14_code = 120

    def __init__(self):
        super().__init__()

    def func(self, blk: ida_hexrays.mblock_t, ins, optflags):
        current_insn = blk.head

        while current_insn != blk.tail and current_insn is not None:
            left_op = current_insn.l
            if current_insn.opcode == ida_hexrays.m_mov and left_op.t == ida_hexrays.mop_r and left_op.r == self.r14_code:
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
                regsvec = ida_hexrays.mopvec_t()
                return_mop = ida_hexrays.mop_t()
                return_mop.make_reg(current_insn.d.r, 8)
                regsvec.push_back(return_mop)

                # set the function return locations
                regslist = ida_hexrays.mlist_t()
                regslist.add(current_insn.d.r, 8)

                # set the location of the returned value
                retloc = ida_typeinf.argloc_t()
                retloc.set_reg1(current_insn.d.r)

                # set the registers spoiled by this function
                spoiledlist = ida_hexrays.mlist_t()
                spoiledlist.add(current_insn.d.r, 8)

                # set all of the callinfo information
                callinfo.return_type = return_type
                callinfo.retregs = regsvec
                callinfo.return_regs = regslist
                callinfo.spoiled = spoiledlist
                callinfo.return_argloc = retloc
                callinfo.flags = ida_hexrays.FCI_NOSIDE
                callinfo.cc = ida_typeinf.CM_CC_FASTCALL

                # set the actual micro instrucion
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
    flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_FIX
    wanted_name = "GoAnalyzer"
    GOANALYZER_NODE = "GoAnalyzerNode"

    def init(self):
        # only 64 bit go has the abi we fix
        if not ida_ida.inf_is_64bit():
            return ida_idaapi.PLUGIN_SKIP

        # go version is specified in the data/go.buildinfo sections, check it
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
        if version_string_len is None or version_string_len > 15 or version_string_len < 5:
            return ida_idaapi.PLUGIN_SKIP

        # we probably have the go version string
        supposed_version_string = ida_bytes.get_bytes(seg_start + VERSION_STRING_OFFSET + 1, version_string_len).decode("ascii")
        match = go_version_regex.match(supposed_version_string)
        MINIMAL_REGISTER_ABI_GO_VERSION = 17
        # check if the go version is higher than 1.17 which means that the register abi is on
        if not match or int(match.group(1)) < MINIMAL_REGISTER_ABI_GO_VERSION:
            return ida_idaapi.PLUGIN_SKIP

        print(f"Detected {supposed_version_string}")

        if not ida_hexrays.init_hexrays_plugin():
            return ida_idaapi.PLUGIN_SKIP

        # initialize our netnode, we don't want to recompile everything all the time
        self.node = ida_netnode.netnode()
        self.node.create(GoAnalyzer.GOANALYZER_NODE)
        self.hooks = CallAnalysisHooks(self.node)
        self.hooks.hook()

        # install the xmm15 zero operand optimizer
        self.filter = Xmm15Optimizer()
        ida_hexrays.install_microcode_filter(self.filter, True)

        # create the goroutine struct if it doesn't already exist
        if not ida_struct.get_struc_id("runtime_g"):
            ida_struct.add_struc(BADADDR, "runtime_g")
        # install the r14 current goroutine optimizer
        self.optimizer = R14Optimizer()
        self.optimizer.install()

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return GoAnalyzer()
