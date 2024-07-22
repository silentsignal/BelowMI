IBM i is a vertically integrated system, where the vendor has full control over both hardware and software from the operating system to the CPU. The tight control over the platform allowed IBM to create a completely abstract development environment, so applications can become truly independent from the underlying hardware, implementing full backwards compatibility. This is achieved through the Machine Interface (MI): an intermediate translation layer between program logic and native code. MI instructions work on "objects" instead of raw (virtual) memory. This object-oriented design and its supporting safety mechanisms implemented in the translator (the component responsble for generating native from intermetiate representations of programs) pose uniqe challenges in the exploitation of memory safety issues on IBM i. 

In this writeup we provide a summary of technical information crucial to evaulate the exploitability and impact of memory safety problems in IBM i programs. As administrators and developers of IBM i aren't supposed to work "below MI level" this kind of information is not officially documented by the vendor. The information presented here is thus based on already published reverse engineering results[^3][^4], and our own findings uncovered using IBM's System Sertice Tools (SST) and the POWER-AS specific Processor [extensions](https://github.com/silentsignal/PowerAS) we developed for the Ghidra reverse engineering framework. 

Tests were performed on a physical POWER 9 system running IBM i V7R4. Programs were compiled by the default settings of the system in the ILE program model. C language source code are [provided separately](https://github.com/silentsignal/SAVF).


## The POWER ISA

Current IBM i platforms are built around IBM's POWER CPU. POWER implements the PowerPC ISA (IBM is one of the founding members of the PowerPC Alliance), extended with vendor-specific instructions, related primarily to memory tagging - commonly referred to as POWER-AS (the name originating from the AS/400 era). The processors implement the 64-bit, big-endian specification.

While the CPU registers are 64-bits wide, IBM i makes use of 128-bit (thick) pointers. Because of this, word lengths are denoted as follows:

* QWORD: 128 bits (thick pointer size)
* DWORD: 64 bits (register size)
* WORD:  32 bits (instruction size (not considering VLE))
* HWORD: 16 bits (half word)

## Security Levels

IBM i's operating system can run in multiple security modes. The QSECURITY System Value (system-wide setting) on IBM i defines the following Security Levels:

* 10 - No Security
* 20 - Password Security
* 30 - Resource Security
* 40 - Operating System Security
* 50 - C2 Level Security

This writeup focuses on Security Level 40 that is the minimum recommended level. Security Level 50 was introduced to meet NCSC's Class C2 security criteria - it is not widely used, likely because incompatibilities it introduces with existing 3rd party software.

## Single-Level Storage

IBM i implements a storage model typical to the platform: Single-Level Storage (SLS) is a model where main storage (memory) and secondary storage (typically SSDs) are treated as a single 64-bit virtual address space.

Virtual addesses in the SLS consist of two parts: a 40-bit segment identifier, and a 24-bit offset inside the segment:

```
Virtual Address: 0xb4d5391dff001122
Segment:         0xb4d5391dff
Offset:                    0x001122
```

The PowerPC architecture supports segment tables, that can be used by the operating system to contol the set of segments accessible by a particular process. However, on IBM i below Security Level 50 this translation mechanism is not in use - all virtual address of the SLS can be accessed by any process.[^6] Compared to common architectures where separate virtual memory is created for individual processes, SLS increases the impact of memory safety violations and add new attack vectors to consider:

| Threat | Impact on per-process virtual memory | Impact on SLS |
| ------ | ------------------------------------ | ------------- |
| Memory safety violations when parsing untrusted data | Access to the address space of the affected process. Use of OS facilities with the privileges of the affected process through arbitrary code execution. | Access to all user-space storage. |
| Execution of untrusted code, no safety violations. | Use OS facilities with the privileges of the executing user through arbitrary code execution. | Use OS facilities with the privileges of the executing user through arbitrary code execution. |
| Execution of untrusted code, deliberately introducing safety violations. |  Use OS facilities with the privileges of the executing user through arbitrary code execution. | Access to all user-space storage. |

[Link to dynamic demonstration](#TODO)

Security of memory accesses is guaranteed by the translator via memory tagging and typed pointers as discussed in later sections. 

Address translation involves enforcing page protection when accessing virtual addresses. A two-bit field (PP) in each Page Table Entry controls whether load or store operations can be performed on a particular page (no separate "execute" protection bit is present). System-state programs can bypass most of these checks[^5].

## Program Serialization

### String constants

String constants are loaded based on R2. An array of string pointers is located at R2, the array contains 0x10 byte structures pointing to variable length, NULL terminated strings.
A typical use of the string table is as follows (TYPES.C):

```asm
e9 42 00 20     ld         r10,0x20(r2) ; R10 := string table address
61 5e 00 00     ori        r30,r10,0x0  ; R30 := R10 
...
39 5e 00 10     addi       r10,r30,0x10 ; R10 := first string pointer from the string table
...
60 88 00 00     ori        r8,r4,0x0    ; Thick pointer type
61 49 00 00     ori        r9,r10,0x0   ; Thick pointer address <- R10
f9 05 00 22     stq        r8,0x20(r5)  ; Store thick pointer on callee stack
...
4b ff ff 11     bl         printf       
```


## Below MI

### Calling Convention(s)

    Future work: Currently this section covers intra-program function calls but should be expanded to cover other call types (e.g. PGM->SRVPGM) and eventually to cover the wider ABI.

To understand how IBM i programs operate at the native instruction (RISC) level, including how control-flow can be redirected in case when programs reach unexpected states, it's crucial to understand how control is transfrerred between program functions. 

According to PowerPC register usage conventions for AIX[^7] (another POWER-based system by IBM) the stack pointer is stored in R1. On IBM i we will of course see something different.

A typical function prologue would look like this (main@CALLCONV):

```asm
fb 41 ff 30     std        r26,-0xd0(r1)    ; Save registers ...
fb 61 ff 38     std        r27,-0xc8(r1)    ; ... r26-r32 ...
fb 81 ff 43     stmd       r28,-0x30(r1)    ; ... "above" R1
7c 08 02 a6     mfspr      r0,LR            ; ... Save link register in R0
f8 01 00 28     std        r0,0x28(r1)      ; Store linkage address in memory "below" R1
f8 21 fe c1     stdu       r1,-0x140(r1)    ; Save R1 in memory
f8 41 00 20     std        r2,0x20(r1)      ; Save r2 in memory
3c 00 44 13     lis        r0,0x4413        ; 
f8 01 00 08     std        r0,0x8(r1)       ;
33 ff 00 60     addic      r31,r31,0x60     ; Grow R31 to higher
7c 20 01 c8     txer       0x1,0x0,0x3      ; The undocumented TXER instruction traps if the stack would overflow its segment.
```

R1 is only used afterwards to restore the saved R2 values after function calls:

```
4b ff fd d1     bl         fflush
e8 41 00 20     ld         r2,0x20(r1)
```

We can observe more frequent use of R31 in the function body, suggesting this register being primarily used to access local variables. The incrementation of this register value also suggests that the stack grows in the positive direction. This is a simple loop (LOOPS.C):

```c
    for (int i=0; i<100; i+=10){
        printf("Outer loop: %d\n",i);
        inner(i);
    }
```

... and its corresponding RISC code:

```asm
loop:
... printf function call ...
e8 9f ff a2     lwa        r4,-0x60(r31)    ; Load i as first register parameter (R4)
39 1f ff b0     subi       r8,r31,0x50      ; Callee stack...
61 03 00 00     ori        r3,r8,0x0        ; ... in R3
4b ff fe 61     bl         inner            ; Function call
e8 bf ff a2     lwa        r5,-0x60(r31)    ; i in R5
39 85 00 0a     addi       r12,r5,0xa       ; Increment i by 10 
7d 8c 07 b4     extsw      r12,r12          ; Sign extend the result
91 9f ff a0     stw        r12,-0x60(r31)   ; Save the new i value
e9 5f ff a2     lwa        r10,-0x60(r31)   ; Load the new i value for comparison
2d 0a 00 64     cmpwi      cr2,r10,0x64     ; Compare i to 100
41 d5 80 23     bgtla      cr5,SUB_ffffffffffff8020
41 88 ff a0     blt        cr2,loop         ; Loop branch
```

We also can confirm that R31 is used as a stack pointer and the direction of stack growth by taking a look at how a functions return value is saved to a local variable:

```c
int num;
int res;
// ...
res=myfunc(num);
```

The compiled RISC code corresponding to the last line is this:

```asm
4b ff fc e9     bl         myfunc         ; Function call
60 64 00 00     ori        r4,r3,0x0      ; R3 is the return value, copy it to R4
90 9f ff a4     stw        r4,-0x5c(r31)  ; Store the WORD part of the result relative to R31
```

As we can see, the integer store operation (`stw`) addresses memory based on R31 and uses a negative offset.

R31 is previously saved in function prologue using the undocumented `stmd` (likely "Store Multiple Doubleword") instruction, and is restored in the function epilogue with the undocumented `lmd` (likely "Load Multiple Doubleword") instruction. The following example instruction loads DWORD's from memory to R26-R31:

```asm
eb 41 ff 33     lmd        r26,-0x34(r1) 
```

Compilers for RISC generally prefer parameter passing in registers, relying on the high register count of these platforms. Since typed pointers of IBM i don't fit into registers, passing pointer arguments requires the use of a stack. The ILE C compiler uses a dedicated stack pointer, R3 to keep track of pointer arguments. R3 and R31 point to the same segment, so it's fair to say that local variables and function parameters use the same stack, only there are two different stack pointers. 

This is how a function call translated from ILE looks like at the callers side:

```asm
subi       r10,r31,0x40     ; Set parameter stack location
lq         r8,r31,0xff9     ; Load thick pointer value from stack
stq        r8,local_60(r10) ; Store thick pointer on user stack
li         r4,0x4           ; Const parameter passed in register (R4,...)
ori        r3,r10,0x0       ; Copy pointer to thick pointer stack to R3
bl         hexprint         ; hexprint(strPtr, 4);  
```

At the callee side the function prologue copies the R3 value to R29, and later pointer access is done via this latter register, while R3 is used as return value (for fitting types). 

In the function epilogue saved registers are restored, then the Link Register is set to the saved caller address, so an appropriate branch instructions (e.g. `blrl`) can transfer control back to the caller:

```
addi	   r1,r1,0x100
ld		   r0,0x28(r1)	; No tag check!
mtspr	   LR,r0
; ... Restoring register context ...
blrl	
```

Note, that the `ld` instruction used to load the caller address from memory doesn't perform a tag check, so the segment pointed by r1 can be an attractive target to exploit memory corruptions. However, dynamic tests show that this segment is different from the ones assigned to standard variables/buffers (R31, R3, R29), so there is no starting point from which the critical data stored here can be reached (see Segment Boundary Checking). 

### Memory Safety

MI doesn't provide memory safety. It is trivial to create an ILE C program that accesses memory outside of a character buffers bounds (OOB.C):

```c
#include<stdio.h>

int main(){
    char buf[4];
    int num;

    scanf("%x %s", &num, buf);

    // Out-of-bounds read in both directions
    for (int i=-2; i < 8; i++){
        printf(" %02x ", buf[i]);
    }

    printf("\n%x\n", num);
    
    return 0;
}
```

A sample execution of the above program produces the following result:

```
> 1337 ABCDE                             
  40  40  c1  c2  c3  c4  c5  00  13  37
  c5001337                               
```

The result clearly shows that both out-of-bounds read and write operations completed without errors (characters are EBCDIC encoded). It's worth noting that the compiler doesn't seem to perform variable reordering to mitigate out-of-bounds access.

Since there is a single instance of any objects in the SLS, parts of program objects (code, compiled-in data, etc.) will occur at the same virtual addresses (in the same segments) for each run. Program addresses change when a program is recompiled. When a user executes a program, segments specific to that particular process (Associated Space, e.g. for stacks and heaps) are associated at random addresses.

While spatial and temporal memory safety are not enforced, the Security Features to be discussed aim for enforcing control-flow integrity (CFI) with compile-time checks: 

* Pointer tagging prevents dereferencing corrupted code pointers.
* Type checking prevents branching to data pointers even if they aren't corrupted.
* Segment Boundary Checks limit the range of memory reachable by offsetting valid pointers through existing application logic. This feature: 
  * enables the translator to protect critical data (e.g. return addresses) by separating them from standard variables
  * reduce the number of reusable variables (e.g. character buffers containing CL commands; code pointers to abusable functions)


### Security Features

#### Pointer Tagging

Pointer tagging is used to guarantee the integrity of pointers on the system. Every aligned QWORD has an additional tag bit, that signals: 
 
> "This pointer is trusted, as it was created by the system" 

Pointer tagging prevents setting pointers to arbitrary values through a write primitive obtained (possibly) by exploiting a memory corruption bug.

QWORDs can be tagged by first issuing a `settag` instruction. This instruction is unprivileged, and the only reason it can't be issued at will is that users can't normally write RISC code to the system. A subsequent `stq` instruction will store a QWORD value at a specified memory address from a pair of 64-bit registers. It's important to note that tag bits are not stored as part of the pointer values, but separately from the primary storage, possibly encoded in the ECC value mainained by the memory controller. 

The following snippet shows calling the `printf` function ("imported" from the standard library) and setting its first format string parameter:

```asm
e9 42 00 20     ld         r10,0x20(r2)   ; Global string table address is loaded to R10
61 5e 00 00     ori        r30,r10,0x0    ; R30 := R10
39 3e 00 40     addi       r9,r30,0x40    ; R9 points to the format string inside the string table
39 1f ff b0     subi       r8,r31,0x50    ; R8 points to a local variable
38 e0 00 80     li         r7,0x80        ; Two instructions load the ...
78 e7 c1 c6     rldicr     r7,r7,0x38,0x7 ;  ... pointer type 0x8000000000000000 to R7
7c 01 03 e6     settag                    ; Next store instruction is tagged
60 e4 00 00     ori        r4,r7,0x0      ; Copy typed pointer from R7, R9 to  ...
61 25 00 00     ori        r5,r9,0x0      ; ... consecutive registers R4||R5
f8 88 00 22     stq        r4,0x20(r8)    ; Store the tagged & typed pointer after R8
61 03 00 00     ori        r3,r8,0x0      ; Set the stack for pointer parameters before branch
4b ff fe a9     bl         printf         ; Call printf("<format string>")
```

The LQ instruction used to load thick pointers in a single instruction will also set a bit in register XER based on the tag bit associated with the target QWORD. This bit is then checked with a TXER ("Trap on XER") instruction emitted together with LQ by the translator. In case the pointer was written to without a previous `settag` (e.g. as a result of a buffer overflow) the tag gets erased, LQ will not set XER, and TXER will cause an exception, terminating the process on unsafe pointer dereference. 

This is part of the source code of a simple program that works with function pointers (FPTRLOOP):

```c
int main(){
    void (*myCmd)();

    for(int i = 0; i < 4; i++){
        if (i % 2 == 0){
            myCmd = func0;
        }else{
            myCmd = func1;
        }
        myCmd();
    }

    return 0x1337;
}
```

This is the corresponding disassembly:

```asm
40 92 00 24     bne        cr4,LAB_11dbd7ca25002174             ;if(){} branch
e9 42 00 28     ld         r10,0x28(r2)                         ;Store the first fptr from 0x28(R2) 
                                                                ;See other branch for details!
; ...SNIP ...
e9 02 00 30     ld         r8,0x30(r2)                          ;R2 points to a global symbol table 
                                                                ;This is the second function address at offset 0x30
                                                                ;Note: untagged load, R2 points to a 
                                                                ;"protected" segment
38 c0 00 a1     li         r6,0xa1                              ;R6 -> Type identifier
78 c6 c1 c6     rldicr     r6,r6,0x38,0x7
7c 01 03 e6     settag
60 c4 00 00     ori        r4,r6,0x0                            ;R4 := R6 (fptr type tag)
61 05 00 00     ori        r5,r8,0x0                            ;R5 := R8 (fptr address)
f8 9f ff d2     stq        r4,-0x30(r31)                        ;Store tagged function pointer 
                                                                ;to stack variable
38 7f ff e0     subi       r3,r31,0x20                          ;Setup callee parameter stack pointer
e9 42 00 08     ld         r10,0x8(r2)
e1 1f ff d1     lq         r8,-0x30(r31)                        ;R8||R9 := Saved fptr
7c 00 05 48     txer       0x0,0x0,0xa                          ;Check if previous load was tagged
61 26 00 00     ori        r6,r9,0x0                            ;R6 := fptr address
61 07 00 00     ori        r7,r8,0x0                            ;R7 := fptr type
e9 66 00 00     ld         r11,0x0(r6)                          ;R11 := Dereferenced function address
e8 ab 00 20     ld         r5,0x20(r11)
7d 2a 28 00     cmpd       cr2,r10,r5
40 8a 00 1c     bne        cr2,LAB_11dbd7ca250021d0
e8 8b 00 08     ld         r4,0x8(r11)                          ;R11 is the head of the thick pointer
                                                                ;R4 is the jump target
7c 89 03 a6     mtspr      CTR,r4
e8 4b 00 00     ld         r2,0x0(r11)
4e 80 04 21     bctrl                                            ;xxx Indirect Call xxx
```

It is important to note that while dereference of "base" pointers (as in a pointers created by the system) is guarded by tags, pointer arithmethic is not - see Memory Safety! 

[Link to dynamic demonstration](#TODO)


#### Segment Boundary Checking

Segment Boundary Checking ensures that pointer arithmetic can only result in pointers within the original segment (even though flawed pointer arithmetic may have caused out-of-bounds access).

The following C function accepts a pointer to a character array, so it can be used to demonstrate pointer dereference (CALLPTR.C):

```c
void myprint(char* str, int n){
    printf("Here is part of your message:\r\n");
    for (int i = 0; i<n; i++){
        putchar(str[i]);
    }
    printf("\r\n");
    fflush(stdout);
}
```

The `str[i]` expression looks like this at the level of RISC code:

```asm 
e5 1d 00 21     ltptr      r8,0x2(r29),0x2  ; Load address from typed pointer to R8
7c e8 62 14     add        r7,r8,r12        ; Add offset (R12) to address, result in R7 
7f a7 40 88     td         0x1d,r7,r8       ; Trap conditionally
88 c7 00 00     lbz        r6,0x0(r7)       ; Load byte from R7
```

Thanks to the [work of Hugo Landau](https://www.devever.net/~hl/ppcas) we know that the `ltptr` instruction is partially documented in [this patent](https://patents.google.com/patent/US20090198967A1/en). According to this document `ltptr` loads NULL to the target register if the tag bit is not set. 

Based on our dynamic tests the conditional trap (`td`) is required to check whether the resulting pointer is beyond a segment boundary (offset 0xffffff) to prevent moving pointers to valid segments other than their original. When passing a value in `n` that would result reading beyond page boundary, the program terminated with and exception. In the above example `td` compares the values of R7 (original pointer) and R8 (incremented pointer). According the public POWER ISA documentation the conditions of trap are these:

```
a <- (RA)
b <- (RB)
if (a < b) & TO0 then TRAP
if (a > b) & TO1 then TRAP
if (a = b) & TO2 then TRAP
if (a <u b) & TO3 then TRAP
if (a >u b) & TO4 then TRAP
```

In the above example the value of the 5-bit TO field is 0b11101. This means that `td` should always trap, but since under normal circumstances (low offset values) pointer dereference works as expected, there is either an OS-level trap handler, or some undocumented behavior involved in the execution of this instruction. Since handling a trap at every valid pointer load would likely have detrimental performance cost, `td` likely has undocumented behavior supporting segment boundary checks. 

For reference we created statistics of the TD masks from the QZSRAAU program. As we can see, similar "impossible" configuration of the TO field is the rule instead of the exception in case of X-form `td` instructions:
```
td_masks.py> Running...
TD Mask: 0b11100 - 44 instances found
TD Mask: 0b11101 - 4 instances found
td_masks.py> Finished!
```

Note that the above check itself should not break normal programs, since according to our tests memory allocations fail when requested size is above 0xffefff. Tests were conducted using malloc (single allocation), and by allocating stack space (e.g. two 0x800000 byte buffers). The observation is also confirmed [here](https://archive.midrange.com/rpg400-l/201310/msg00307.html), noting that terraspace may be useful to expand this limit - this needs further research. 

The leaked PPCAS documentation of the `td` instruction includes the following logic for the 0b11100 mask value:

```
if ( a0:15 =/ b0:15 |
( a0:15 =/ 0 &
( ( a16:39 =/ b16:39) | (a < b) ) ) ) &
TO = 0b11100 & (tags active) then TRAP
```

Checks on bits [0,39] of the input register values confirms our previously stated result. While the 0b11101 mask is not even documented in the internal documentation (dated to 1999.), it is reasonable to assume that the trap logic works similarly in this case too. 

To confirm the working and significance of segment boundary checking the program S2DBG was created. The program includes the following almost trivial function:

```c
char* increment(char* p, long long l){
    return p+l;
}
```

The program expects the user to replace (patch) the `td` instruction generated as part of the above function with a NOP instruction (this requires access to SST with high privileges, but this is beside the point of the demonstration, as it is not supposed to be an exploit). After the single `td` instruction was patched, S2DBG allows reading and writing arbitrary memory, including segments belonging to QSECOFR (page protections still apply though). This behavior also confirms the threat model outlined in the Single-Level Store section on modern IBM i versions. 

[Link to Demo](https://vimeo.com/976308689)

#### Typed Pointers

Another security measure implemented by IBM i is associating type metadata to pointers.[^1] Typed, or "thick" pointers are aligned QWORDs, consisting of two DWORDs each: the first DWORD identifies the type, while the second is the 64-bit virtual address in the SLS. Typed pointers are supported by memory tagging: changing the type portion would break the memory tag just as changing the address portion would. 

Type checking becomes important when otherwise valid (tagged) pointers are to be used in the wrong context, e.g. treating a "data" pointer as a "code" pointer. ILE C supports "open pointers" (`void *`), so there is no language-level constraint that would prevent such misuse (as opposed to e.g. inline assembly).  We know that no separate execution permissions exist at a page level, thus any readable address should be executable too, so page protection will not cover this scenario. The following sample program was created to gain a better understanding of this scenario (DEREF2.C):

```c
void derefFuncPtr(void* ptr){
    char *dummy="xxxx";
    void (*fp)(char*) = ptr;
    fp(dummy); // Avoid dead code elimination
}

int main(){
    char buf[16];
    scanf("%s", buf);
    derefFuncPtr(derefChar);
    return 0x1337;
}
```

Here is the RISC code generated for the function pointer declaration in `derefFuncPtr`:

```asm
e1 1f ff b1     lq         r8,-50(r31),0x01                   ; Pointer from stack in R8||R9
                                                              ; Last four reserved bits are: 0b0001
7c 00 05 48     txer       0x0,0x0,0xa                        ;  Trap if not tagged (and type incorrect?)
61 2a 00 00     ori        r10,r9,0x0                         ;  Function address -> R10
61 0c 00 00     ori        r12,r8,0x0                         ;  Funcptr type -> R12
60 e3 00 00     ori        r3,r7,0x0                          ; Setting callee parameter stack 
e9 6a 00 00     ld         r11,0x0(r10)                       ;  Dereference function address to R11
e8 ab 00 20     ld         r5,0x20(r11)
7d 26 28 00     cmpd       cr2,r6,r5
40 8a 00 1c     bne        cr2,label_error
e8 8b 00 08     ld         r4,0x8(r11)                        ; Another deref from R11 to R4
7c 89 03 a6     mtspr      CTR,r4                             ; Set program counter from R4
e8 4b 00 00     ld         r2,0x0(r11)
4e 80 04 21     bctrl                                         ; Branch to CTR

```


Based on our tests in the above case (and similar ones) LQ not only traps if the loaded pointer was not tagged, but also if the mask encoded in the instruction (third operand in the above disassembly) doesn't correspond to the type of the loaded thick pointer.

##### Identifying Type Tags and Masks

When we take a look at the disassebly of a regular program shipped with the OS, we see two other common masks - output of `lq_masks.py` on QZSRAAU:

```
lq_masks.py> Running...
LQ Mask: 0x2 - 133 instances found
LQ Mask: 0xF - 75 instances found
lq_masks.py> Finished!
```

Based on the disassembly of our example programs we could observe that pointer types are set using two instructions:

* `li` (Load Immediate) is used to load a single byte to a register. This byte is the type identifier.
* `rldicr` (Rotate Left Doubleword Immediate then Clear Right) is used to move the type byte to MSB, filling the other part of the value with zeroes.

When we look for `li`-`rldicr` sequences in the QZSRAAU program we can identify the following type bytes - output on `tag_bytes.py` on QZSRAAU:

```
tag_bytes.py> Running...
Tag: 0x80 - 64 instances found
Tag: 0x00 - 1 instances found
Tag: 0x01 - 1 instances found
Tag: 0xA2 - 24 instances found
tag_bytes.py> Finished!
```

Based on the above observations we theorize the following relations between LQ mask values and type identifiers:

| Type Byte | LQ Mask | Comment |
|-----------|---------|---------|
| 0x80      | 0xF     | Union of sample code and QSZRAAU results. |
| 0xA1      | 0x1     | See function pointer examples! |
| 0xA2      | 0x2     | See QZSRAAU results vs. example code |

The above results are partially confirmed by the internal PPCAS documentation:

* The 42nd bit of XER is set if the the MSB of the loaded typed pointer equals to `0xA || LQ mask` (`||` denotes concatenation). In the above example, the subsequent `txer` instruction traps if the 42nd bit (32+XBI) of XER is 0.
* The `DECODE` operation performed by `lq` on the most significant two bits of the loaded thick pointer always results in a non-zero value. The `DECODE` output AND-ed to the 0xF mask thus always results in non-zero, setting the 41st bit of XER. A subsequent `txer` instruction with XBI=9 can then check this bit.


[Link to dynamic demonstration](#TODO)

### Evaluation

#### Data-Only Exploitation - Out-of-Context Call

The following code is part of a deliberately exploitable sample program that demonstrates the exploitability of (some, highly constrained) memory corruption bugs (CRACKMEX.C):

```c
int main(){
    void (*adminCmd)(char*);
    Command commands[2];
    char param[256];
    int cmd = 0;

    commands[1].name="lower";
    commands[1].exec=lower;
    commands[0].name="upper";
    commands[0].exec=upper;

    adminCmd = my_system;

	// ...

    while(cmd != 99){
        menu();
        scanf("%d", &cmd);
        if (cmd == 99) break;

        printf("Parameter: ");
        fflush(stdout);

		// ...

        fgets(param, 256, stdin);

		// ...

        Command *tmpCmd = &(commands[cmd]);
        printf("%llx %llx %llx %llx\n", *tmpCmd);
        printf("Invoking %s(%s)\n", tmpCmd->name, param);
        tmpCmd->exec(param);

    }
    return 0x1337;
}

```

In this example `upper()` and  `lower()` are harmless functions, while `my_system()` is a simple wrapper around the built-in `system()` function that provides some console output for debugging. 

As we can see, the `commands` array of function pointers can be trivially under/overindexed. By providing the value -1 to `cmd` it's possible to invoke the `adminCmd` pointer also residing on the stack, achieving command execution:

```
0) UPPERCASE
1) lowercase
99) Exit
> -1
Parameter: 
===> wrkobj qgpl/crackemex
```

[Link to demo](https://vimeo.com/976340326)

# Footnotes and References

    Thorough referencing is WIP!

[^1]: This may remind astute readers of capability based addressing, which was present in AS/400 until V1R3, but is no longer in use in user-state programs, since pointer capabilities couldn't be revoked. [@soltis:1996:inside]

[^3]: https://www.devever.net/~hl/ppcas

[^4]: https://svalgaard.leif.org/as400/

[^5]: Soltis - Inside the AS/400, p. 203., 215.

[^6]: See 'Chapter 7 - Accessing Arbitrary Data in Memory' in Leif SvalGaard's MI Programming

[^7]: https://www.ibm.com/docs/en/aix/7.2?topic=overview-register-usage-conventions

