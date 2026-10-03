# CTF Prep — Reverse Engineering & Binary Exploitation

Quick-reference to move fast on rev/pwn during the comp. Bring me the actual binary/output and I'll work the specific challenge with you.

## Toolbox (install before Saturday)
```
# static / triage
file ./bin ; strings -n6 ./bin ; nm ./bin ; readelf -a ./bin ; objdump -d -Mintel ./bin
checksec --file=./bin            # pwntools: mitigations at a glance
# disassemblers / decompilers
Ghidra (free, great decompiler) ; IDA Free ; Binary Ninja ; radare2/rizin+cutter
# dynamic
gdb + GEF or pwndbg            # runtime, heap, patterns
ltrace ./bin ; strace ./bin    # lib/syscall calls
# exploit dev
python3 + pwntools             # pip install pwntools
one_gadget ./libc.so ; ROPgadget --binary ./bin ; ropper
```

## Reverse engineering — workflow
1. `file` + `checksec` — arch, static/dynamic, PIE/NX/canary/RELRO.
2. `strings` — flags, format strings, hints, passwords, `system` args.
3. Load in Ghidra → find `main` → read decompiled C.
4. Look for the check: password compare (`strcmp`/`memcmp`), math on input, XOR/base64 obfuscation.
5. Recover the algorithm → reverse it in Python to compute the required input/flag.
6. Common tricks: hidden funcs never called (jump to them), `ptrace` anti-debug (patch out / `LD_PRELOAD` stub), packed with UPX (`upx -d`).

## Binary exploitation — decision tree by mitigations
`checksec` tells you the path:

| Seen | Technique |
|---|---|
| No canary, NX off | classic **stack buffer overflow → shellcode** on stack |
| No canary, NX on | **ret2libc / ROP** (return to `system("/bin/sh")` or `execve` ROP chain) |
| Canary on | need a **leak** (format string / OOB read) to defeat canary first |
| PIE on | need an **address leak** to defeat ASLR, then rebase your gadgets |
| Full RELRO | no GOT overwrite — pivot to ROP / `__malloc_hook` etc. |
| `printf(user)` | **format string**: `%p` leaks, `%n` writes (GOT/return addr) |
| heap chunks / `free` | **heap**: UAF, double-free, tcache poisoning (glibc-version dependent) |

## Offsets + leaks — the usual moves
```python
from pwn import *
# 1) find overflow offset
cyclic(200)                          # send it, crash, read $rip
cyclic_find(0x6161...)               # -> exact offset to return address
# 2) leak libc (ret2plt puts(puts@got) then return to main)
# 3) compute base: libc.address = leak - libc.symbols['puts']
# 4) build chain
rop = ROP(libc); rop.system(next(libc.search(b'/bin/sh')))
```

## Format string cheat
- `%p %p %p ...` — dump stack, find your input's index.
- `%7$p` — direct param access (index 7 here).
- `%n` writes # bytes printed so far to an address on the stack — pair with `pwntools` `fmtstr_payload()`.

## Fast checklist per pwn challenge
- [ ] `checksec` → pick technique from table
- [ ] find input → crash → `cyclic` offset
- [ ] NX? need ROP. PIE/canary? need leak first
- [ ] get libc base (leak a GOT entry via puts/printf)
- [ ] `system("/bin/sh")` or `execve` ROP → shell → `cat flag`
- [ ] remote: `p = remote(host, port)` then same payload

## When you're stuck, send me
- output of `file`, `checksec`, `strings`
- the Ghidra decompiled `main` (paste it)
- the crash / gdb backtrace
- for pwn: the binary's protections + any leak you already have

I'll help derive the offset, build the ROP chain, or reverse the algorithm live.
