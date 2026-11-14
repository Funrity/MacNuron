#!/usr/bin/env python3
"""
Fallback AArch64 assembler & linker using system libLLVM.so when clang/lld bin packages
are not installed on the host, plus minimal zlib header/symlink setup for libz.so.1.
"""
import ctypes, os, re, struct, sys

def find_libllvm():
    for name in ("libLLVM-19.so", "libLLVM-18.so", "libLLVM-17.so", "libLLVM-16.so", "libLLVM.so"):
        for d in ("/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    raise RuntimeError("libLLVM shared library not found")

def strip_cpp_comments(src: str) -> str:
    # Strip /* ... */ and // ... comments as clang preprocessor does for .S files
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.DOTALL)
    lines = []
    for line in src.splitlines():
        idx = line.find('//')
        if idx != -1:
            line = line[:idx]
        lines.append(line)
    return '\n'.join(lines) + '\n'

def llvm_assemble(src_text: str, triple=b"aarch64-none-elf", cpu=b"generic", features=b"+v8.3a,+lse,+crypto,+fp-armv8,+neon") -> bytes:
    clean_bytes = strip_cpp_comments(src_text).encode("utf-8")
    llvm = ctypes.CDLL(find_libllvm())
    llvm.LLVMInitializeAArch64TargetInfo()
    llvm.LLVMInitializeAArch64Target()
    llvm.LLVMInitializeAArch64TargetMC()
    llvm.LLVMInitializeAArch64AsmParser()
    llvm.LLVMInitializeAArch64AsmPrinter()

    llvm.LLVMContextCreate.argtypes = []
    llvm.LLVMContextCreate.restype = ctypes.c_void_p
    llvm.LLVMModuleCreateWithNameInContext.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    llvm.LLVMModuleCreateWithNameInContext.restype = ctypes.c_void_p
    llvm.LLVMSetTarget.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    llvm.LLVMSetModuleInlineAsm2.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]

    llvm.LLVMGetTargetFromTriple.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_char_p)]
    llvm.LLVMGetTargetFromTriple.restype = ctypes.c_int
    target = ctypes.c_void_p()
    err = ctypes.c_char_p()
    if llvm.LLVMGetTargetFromTriple(triple, ctypes.byref(target), ctypes.byref(err)) != 0:
        raise RuntimeError(err.value.decode() if err.value else "LLVMGetTargetFromTriple failed")

    llvm.LLVMCreateTargetMachine.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_int, ctypes.c_int
    ]
    llvm.LLVMCreateTargetMachine.restype = ctypes.c_void_p
    tm = llvm.LLVMCreateTargetMachine(target, triple, cpu, features, 0, 0, 0)

    ctx = llvm.LLVMContextCreate()
    mod = llvm.LLVMModuleCreateWithNameInContext(b"asm_mod", ctx)
    llvm.LLVMSetTarget(mod, triple)
    llvm.LLVMSetModuleInlineAsm2(mod, clean_bytes, len(clean_bytes))

    llvm.LLVMTargetMachineEmitToMemoryBuffer.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
        ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_void_p)
    ]
    llvm.LLVMTargetMachineEmitToMemoryBuffer.restype = ctypes.c_int
    llvm.LLVMGetBufferStart.argtypes = [ctypes.c_void_p]
    llvm.LLVMGetBufferStart.restype = ctypes.c_void_p
    llvm.LLVMGetBufferSize.argtypes = [ctypes.c_void_p]
    llvm.LLVMGetBufferSize.restype = ctypes.c_size_t

    out_buf = ctypes.c_void_p()
    if llvm.LLVMTargetMachineEmitToMemoryBuffer(tm, mod, 1, ctypes.byref(err), ctypes.byref(out_buf)) != 0:
        raise RuntimeError(err.value.decode() if err.value else "LLVMTargetMachineEmitToMemoryBuffer failed")

    ptr = llvm.LLVMGetBufferStart(out_buf)
    sz = llvm.LLVMGetBufferSize(out_buf)
    return ctypes.string_at(ptr, sz)

def elf_to_flat_bin(elf: bytes, text_base: int) -> bytes:
    e_shoff, = struct.unpack_from("<Q", elf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", elf, 58)

    def shdr(i):
        off = e_shoff + i * e_shentsize
        return struct.unpack_from("<IIQQQQIIQQ", elf, off)

    shstr_off = shdr(e_shstrndx)[4]
    shstr_sz = shdr(e_shstrndx)[5]
    shstr = elf[shstr_off:shstr_off + shstr_sz]

    def sname(no):
        end = shstr.find(b"\0", no)
        return shstr[no:end].decode()

    sections = {}
    for i in range(e_shnum):
        s = shdr(i)
        sections[sname(s[0])] = (i, s)

    text_idx, text_sh = sections[".text"]
    text = bytearray(elf[text_sh[4]:text_sh[4] + text_sh[5]])

    # Apply .rela.text relocations if present
    if ".rela.text" in sections and ".symtab" in sections:
        _, rela_sh = sections[".rela.text"]
        _, sym_sh = sections[".symtab"]
        rela_data = elf[rela_sh[4]:rela_sh[4] + rela_sh[5]]
        sym_data = elf[sym_sh[4]:sym_sh[4] + sym_sh[5]]

        def get_sym_val(sym_idx):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", sym_data, sym_idx * 24)
            return text_base + st_value

        for off in range(0, len(rela_data), 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", rela_data, off)
            r_type = r_info & 0xffffffff
            r_sym = r_info >> 32
            S = get_sym_val(r_sym)
            A = r_addend
            P = text_base + r_offset
            insn, = struct.unpack_from("<I", text, r_offset)
            if r_type == 275:  # R_AARCH64_ADR_PREL_PG_HI21
                pg = ((S + A) & ~0xfff) - (P & ~0xfff)
                imm = (pg >> 12) & 0x1fffff
                immlo = imm & 3
                immhi = (imm >> 2) & 0x7ffff
                insn = (insn & ~((3 << 29) | (0x7ffff << 5))) | (immlo << 29) | (immhi << 5)
            elif r_type == 277:  # R_AARCH64_ADD_ABS_LO12_NC
                imm12 = (S + A) & 0xfff
                insn = (insn & ~(0xfff << 10)) | (imm12 << 10)
            elif r_type in (282, 283):  # R_AARCH64_JUMP26, R_AARCH64_CALL26
                imm26 = ((S + A - P) >> 2) & 0x3ffffff
                insn = (insn & ~0x3ffffff) | imm26
            struct.pack_into("<I", text, r_offset, insn)

    return bytes(text)

def build_hello_macho(in_s: str, out_macho: str):
    # Assemble hello.S as ELF to get instructions + const string, then wrap in a clean arm64 iOS 14.0 Mach-O
    with open(in_s, "r", encoding="utf-8") as f:
        src = f.read()
    # Replace Mach-O specific syntax with standard ELF gas syntax for instruction assembly on same page
    src_elf = src.replace("msg@PAGEOFF", ":lo12:msg").replace("msg@PAGE", "msg").replace(".section __TEXT,__const", ".p2align 2")
    elf = llvm_assemble(src_elf, triple=b"aarch64-none-elf")
    code_off = 0x200
    vm_base = 0x100000000
    code = elf_to_flat_bin(elf, vm_base + code_off)

    # Construct 64-bit arm64 MH_EXECUTE Mach-O with:
    # 1. LC_SEGMENT_64 (__TEXT, vmaddr=0x100000000, vmsize=0x4000, fileoff=0, filesize=0x4000)
    # 2. LC_BUILD_VERSION (platform=2 iOS, minos=14.0, sdk=14.0)
    # 3. LC_MAIN (entryoff=0x200)
    seg_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19, 72, b"__TEXT".ljust(16, b"\0"),
        vm_base, 0x4000, 0, 0x4000, 5, 5, 0, 0
    )
    build_ver_cmd = struct.pack("<IIIIII", 0x32, 24, 2, 0x000e0000, 0x000e0000, 0)
    main_cmd = struct.pack("<IIQQ", 0x80000028, 24, code_off, 0)
    cmds = seg_cmd + build_ver_cmd + main_cmd
    hdr = struct.pack("<IIIIIIII", 0xfeedfacf, 0x0100000c, 0, 2, 3, len(cmds), 0x200085, 0)

    img = bytearray(0x4000)
    img[0:len(hdr)] = hdr
    img[len(hdr):len(hdr)+len(cmds)] = cmds
    img[code_off:code_off+len(code)] = code
    with open(out_macho, "wb") as f:
        f.write(img)

def setup_zlib(zdir: str):
    os.makedirs(zdir, exist_ok=True)
    zh = os.path.join(zdir, "zlib.h")
    if not os.path.exists("/usr/include/zlib.h"):
        with open(zh, "w", encoding="utf-8") as f:
            f.write("""#ifndef ZLIB_H
#define ZLIB_H
#include <stddef.h>
typedef unsigned char Bytef;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef void *voidpf;
typedef struct z_stream_s {
    const Bytef *next_in;
    uInt avail_in;
    uLong total_in;
    Bytef *next_out;
    uInt avail_out;
    uLong total_out;
    const char *msg;
    void *state;
    voidpf (*zalloc)(voidpf, uInt, uInt);
    void (*zfree)(voidpf, voidpf);
    voidpf opaque;
    int data_type;
    uLong adler;
    uLong reserved;
} z_stream;
#define Z_NULL 0
#define Z_OK 0
#define Z_STREAM_END 1
#define Z_NO_FLUSH 0
#define Z_FINISH 4
#define ZLIB_VERSION "1.3.1"
int inflateInit2_(z_stream *strm, int windowBits, const char *version, int stream_size);
int inflate(z_stream *strm, int flush);
int inflateEnd(z_stream *strm);
#define inflateInit2(strm, windowBits) inflateInit2_((strm), (windowBits), ZLIB_VERSION, (int)sizeof(z_stream))
#endif
""")
    libz_so = os.path.join(zdir, "libz.so")
    if not os.path.exists(libz_so):
        for cand in ("/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libz.so.1", "/lib64/libz.so.1"):
            if os.path.exists(cand):
                os.symlink(cand, libz_so)
                break

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "raw":
        in_s, out_bin, base_str = sys.argv[2], sys.argv[3], sys.argv[4]
        with open(in_s, "r", encoding="utf-8") as f:
            src = f.read()
        elf = llvm_assemble(src)
        flat = elf_to_flat_bin(elf, int(base_str, 0))
        with open(out_bin, "wb") as f:
            f.write(flat)
    elif cmd == "macho":
        build_hello_macho(sys.argv[2], sys.argv[3])
    elif cmd == "zlib":
        setup_zlib(sys.argv[2])
    else:
        raise SystemExit(f"Unknown command: {cmd}")
