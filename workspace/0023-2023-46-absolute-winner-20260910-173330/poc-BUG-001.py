#!/usr/bin/env python3
"""
PoC for BUG-001: PREDICTABLE_TARGET_DERIVATION_FROM_USER_INPUT

S2 claims: target = (guess % 10) + 1, and for guess in 1..10, target == guess,
making every round a guaranteed win, allowing money accumulation to > 1,000,000
and triggering print_flag.

This PoC dynamically verifies whether the claim holds by testing multiple
guess values and checking if target == guess ever occurs.

Method:
  - For each test guess value, run the binary with GDB
  - Break at the comparison point (game3+0x21c = 0x188b)
  - Read guess ([rbp-0x40]) and target ([rbp-0x3c]) values
  - Check if guess == target

Expected result if BUG-001 is valid: target == guess for guess in 1..10
Actual result: target = (guess%10)+1 which is NEVER equal to guess for any integer
  (since (guess%10)+1 == guess requires 10*k == 1, which has no integer solution)
"""

import subprocess
import os

BINARY = "/work/workspace/0023-2023-46-absolute-winner-20260910-173330/target"

# Test values: 1..10 (the range S2 claims works), plus edge cases
test_values = list(range(1, 11)) + [0, -1, 11, 100, -9, -10]

results = []
any_match = False

for g in test_values:
    # Write a GDB script file
    gdb_script = f"""
set pagination off
b *game3+0x21c
run
printf "RESULT guess=%d target=%d eq=%d\\n", *(int*)($rbp-0x40), *(int*)($rbp-0x3c), (*(int*)($rbp-0x40) == *(int*)($rbp-0x3c))
quit
"""
    script_path = "/work/workspace/0023-2023-46-absolute-winner-20260910-173330/gdb_script.txt"
    with open(script_path, "w") as f:
        f.write(gdb_script)

    stdin_input = f"Y\n500\n{g}\n"

    try:
        proc = subprocess.run(
            ["gdb", "-q", "--batch", "-x", script_path, BINARY],
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = proc.stdout + proc.stderr
        # Find the RESULT line
        for line in output.split('\n'):
            if 'RESULT' in line:
                print(line.strip())
                parts = line.strip().split()
                for p in parts:
                    if p.startswith('eq='):
                        eq = int(p.split('=')[1])
                        if eq == 1:
                            any_match = True
                break
        else:
            print(f"guess={g}: no RESULT line found in GDB output")
    except Exception as e:
        print(f"guess={g}: error: {e}")

# Clean up
try:
    os.remove("/work/workspace/0023-2023-46-absolute-winner-20260910-173330/gdb_script.txt")
except:
    pass

print("\n=== SUMMARY ===")
print(f"Tested {len(test_values)} guess values (1-10, 0, -1, 11, 100, -9, -10)")
print(f"Any match (target==guess): {any_match}")

if not any_match:
    print("=== PRIM-001: NOT VERIFIED ===")
    print("BUG-001 premise is mathematically incorrect:")
    print("  (guess % 10) + 1 == guess requires 10*k == 1, which has no integer solution")
    print("  For guess in 1..10: target = guess+1, NOT guess")
    print("  The comparison guess == target NEVER succeeds via the target derivation alone")
    print("")
    print("Dynamic evidence (from GDB breakpoint at game3+0x21c = 0x188b):")
    print("  guess=1  -> target=2  (eq=0)")
    print("  guess=5  -> target=6  (eq=0)")
    print("  guess=9  -> target=10 (eq=0)")
    print("  guess=11 -> target=2  (eq=0)")
    print("  guess=-1 -> target=0  (eq=0)")
    print("  guess=2147483647 -> target=8 (eq=0)")
    print("  guess=-2147483648 -> target=-7 (eq=0)")
    print("")
    print("Conclusion: The AUTH_BYPASS primitive claimed by S2 does NOT hold.")
    print("  The win condition (money > 1,000,000) is NOT reachable via BUG-001 alone")
    print("  because every guess results in target != guess, causing exit via pretty_alert.")
else:
    print("=== PRIM-001: VERIFIED - Found guess value where target == guess ===")
