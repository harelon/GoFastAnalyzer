from ida_kernwin import get_kernel_version

BYTE_SIZE = 8

IDA_MIN_GO_SUPPORT_VERSION = 8.1

GO_SUPPORTED = float(get_kernel_version()) >= IDA_MIN_GO_SUPPORT_VERSION

# list of register names representing the registers used in a go fastcall by their order
go_fast_convention = ["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"]

runtime_morestack_functions = ["runtime.morestack_noctxt", "runtime.morestack"]
