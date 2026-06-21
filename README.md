# PHP 8.1 ionCube Opcode Dumper

This repository contains a Windows x86 PHP extension and a PHP-side export
pipeline that captures complete Zend opcode arrays from ionCube-encoded PHP
files.

The implementation is intentionally tied to the exact runtime bundled in this
repository:

- PHP 8.1.34 NTS, Visual C++ 2019, x86
- Zend Engine 4.1.34
- ionCube PHP Loader 15.5.0
- `runtime/ext/ioncube_loader_win_8.1.dll`
- `runtime/ext/php_opcodedump.dll`

The purpose of this project is to produce a complete and accurate opcode dump
from PHP files encoded with ionCube. The dump must preserve the real Zend
opcodes, operands, literals, compiled variables, exception metadata, and exact
jump targets required to understand or reconstruct the program flow.

To obtain that information, the extension captures each temporary
`zend_op_array` while the loader has fully materialized it, recovers the real
opcode number selected by the VM handler, and preserves all relevant pointers
before the loader releases or reuses its transient memory.

Use this tooling only with files that you are authorized to inspect.

## Runtime Setup

The loader-specific RVAs documented below were identified in:

```text
runtime/ext/ioncube_loader_win_8.1.dll
ionCube PHP Loader 15.5.0
SHA-256: 6C0CD1F063E5C3526946CA5898D7977C4A7F21242DC7A76CA96879D92838DD6B
```

The loader filename alone is not sufficient to identify the analyzed build.
The RVAs and instruction sequences in this document apply to the exact SHA-256
above; another `ioncube_loader_win_8.1.dll` may have different code at the same
addresses.

The bundled runtime uses:

```text
runtime/php.exe
PHP 8.1.34 NTS x86
```

The opcode dumper extension is loaded from:

```text
runtime/ext/php_opcodedump.dll
```

RVA values are loader-relative. At runtime the implementation always calculates
an address as:

```c
absolute_address = (uintptr_t)GetModuleHandleA(
    "ioncube_loader_win_8.1.dll"
) + rva;
```

This is necessary because ASLR changes the module base between processes.

## Quick Start

Build the extension:

```bat
build\build.bat
```

Deploy the resulting DLL:

```powershell
Copy-Item build\out\php_opcodedump.dll runtime\ext\php_opcodedump.dll -Force
```

Dump one encoded file:

```bat
dump.bat sample.php
```

Dump several encoded files:

```bat
dump.bat first.php second.php third.php
```

The command creates two files next to each input:

```text
sample.opcodes.json
sample.opcodes.txt
```

The JSON file is the authoritative structured output. The TXT file is a
human-readable dump of the normalized raw extension output.

## What a Full Dump Means

A complete result includes:

- the top-level `{main}` op-array;
- every user function declared by the file;
- dynamic-key-protected global functions and their key providers;
- every class declared by the file;
- every user method in each class function table;
- closures and dynamic function definitions when available;
- argument metadata and function flags;
- CV variable names;
- literal values and literal indexes;
- every opcode and its numeric value;
- operand types and operand values;
- temporary-variable and compiled-variable slots;
- all control-flow targets;
- try/catch/finally metadata;
- live ranges;
- a derived control-flow graph;
- call, assignment, include, return, and literal-reference indexes.

For example, an encoded class file may expose only this in `{main}`:

```text
ZEND_DECLARE_CLASS
ZEND_RETURN
```

That does not mean the class methods are empty. Their op-arrays live in:

```c
zend_class_entry->function_table
```

The dumper explicitly walks that table and materializes every user method.

## Why a Normal Compile Hook Is Not Enough

Calling `compile_filename()` gives access to the file's Zend structures, but an
encoded function may still be represented by a protected or lazy op-array:

- `op_array->reserved[3]` points to a loader descriptor;
- `op_array->opcodes` may contain a small odd sentinel instead of an aligned
  `zend_op *`;
- `op_array->last` may be zero even though the descriptor contains the real
  opcode count;
- the real opcode body may exist only briefly during materialization or VM
  dispatch;
- the byte stored in `opline->opcode` may be permuted;
- the `opline->handler` pointer is what the loader actually dispatches;
- handler pointers may be encrypted after being selected;
- jump operands are absolute pointers on this x86 build;
- materialized opcode and literal buffers may be released immediately after the
  loader finishes a stage.

Therefore the implementation has four separate responsibilities:

1. Reach the loader's materialization path.
2. Capture the opcode number or recover it from the selected handler.
3. Deep-copy transient opcode/literal memory and rebase internal pointers.
4. Convert absolute pointers into stable indexes for JSON.

## High-Level Architecture

```text
encoded PHP file
       |
       v
compile_filename()
       |
       +--> {main} zend_op_array
       +--> CG/EG function tables
       +--> CG/EG class tables
                 |
                 v
      loader materialization paths
       |          |             |
       |          |             +--> VM-loop entry capture
       |          +----------------> opcode setter capture
       +---------------------------> direct op-array materializer
                 |
                 v
      stable deep-copied snapshots
                 |
                 v
      handler -> real opcode mapping
                 |
                 v
      operand/literal/jump conversion
                 |
                 v
      raw C-extension array
                 |
                 v
      PHP normalization + IR + CFG
                 |
                 v
      .opcodes.json and .opcodes.txt
```

The implementation is split between:

- `src/opcodedump.c`: loader integration, hooks, snapshots, opcode recovery,
  pointer conversion, raw Zend structure export;
- `opcodedump.php`: command-line entry point;
- `lib/normalize.php`: raw-key and structure normalization;
- `lib/ir.php`: structured opcode IR, jump target collection, CFG, indexes;
- `lib/flags.php`: function/class/extended-value decoding;
- `lib/output.php`: output paths and serialization;
- `dump.bat`: reproducible runtime configuration.

## Zend Structures Used by the Dumper

### `zend_op`

On this x86 runtime, one opcode record is exactly 28 bytes (`0x1C`):

| Offset | Size | Field |
|---:|---:|---|
| `+0x00` | 4 | `handler` |
| `+0x04` | 4 | `op1` |
| `+0x08` | 4 | `op2` |
| `+0x0C` | 4 | `result` |
| `+0x10` | 4 | `extended_value` |
| `+0x14` | 4 | `lineno` |
| `+0x18` | 1 | `opcode` |
| `+0x19` | 1 | `op1_type` |
| `+0x1A` | 1 | `op2_type` |
| `+0x1B` | 1 | `result_type` |

The size is visible directly in the loader VM loop:

```asm
; sub_1006FF10
sub eax, opcodes_base
imul/sar ...                 ; divide by 28
```

It is also visible in the materializer:

```asm
1009BD72  add esi, 1Ch       ; advance to the next zend_op
```

### `znode_op`

`op1`, `op2`, and `result` are unions. Their meaning is selected by the
corresponding operand type:

```c
typedef union _znode_op {
    uint32_t constant;
    uint32_t var;
    uint32_t num;
    uint32_t opline_num;
    zend_op *jmp_addr;
    zval *zv;
} znode_op;
```

This means the same four bytes may be:

- a temporary/CV byte offset;
- a literal pointer;
- an absolute jump pointer;
- a numeric flag or argument index.

The type field must always be interpreted before the union value.

An `IS_UNUSED` operand is semantically unused. Its numeric union value may
contain cache data or process-specific values and is not source-level data.

### `zend_op_array`

The loader-relevant x86 offsets are:

| Offset | Field | Use in the dumper |
|---:|---|---|
| `+0x24` | `cache_size` | metadata |
| `+0x28` | `last_var` | CV count |
| `+0x2C` | `T` | temporary-variable count |
| `+0x30` | `last` | opcode count |
| `+0x34` | `opcodes` | opcode-array base |
| `+0x40` | `static_variables` | exported when readable |
| `+0x44` | `vars` | CV-name table |
| `+0x4C` | `last_live_range` | live-range count |
| `+0x50` | `last_try_catch` | try/catch table count |
| `+0x54` | `live_range` | live-range pointer |
| `+0x58` | `try_catch_array` | exception metadata |
| `+0x5C` | `filename` | also contributes to the loader restore key |
| `+0x60` | `line_start` | source metadata |
| `+0x64` | `line_end` | contains a loader materialization marker |
| `+0x6C` | `last_literal` | literal count |
| `+0x74` | `literals` | literal-array base |
| `+0x88` | `reserved[3]` | loader descriptor pointer |

### `zend_execute_data`

At the loader VM entry, `ECX` points to `zend_execute_data`. On x86:

```text
execute_data + 0x0C = execute_data->func
```

The VM-loop detour reads:

```c
zend_op_array *oa =
    *(zend_op_array **)((char *)execute_data + 0x0C);
```

## Loader Descriptor Fields Observed at Runtime

The descriptor is reached through:

```c
uint32_t *desc = (uint32_t *)op_array->reserved[3];
```

The implementation uses the following observed fields:

| Index | Offset | Observed role |
|---:|---:|---|
| `desc[5]` | `+0x14` | encoded/restorable opcode pointer material |
| `desc[6]` | `+0x18` | protected opcode-state pointer |
| `desc[15]` | `+0x3C` | materialized opcode-buffer pointer |
| `desc[16]` | `+0x40` | base used by the restore calculation |
| `desc[17]` | `+0x44` | restore-key component |
| `desc[19]` | `+0x4C` | function/materialization context pointer |
| `desc[21]` | `+0x54` | metadata context used by VM dispatch |
| `desc[25]` | `+0x64` | branch shuffle table A |
| `desc[26]` | `+0x68` | branch shuffle table B |
| `desc[27]` | `+0x6C` | saved opcode count |

The code treats these as loader-specific observed fields, not as a public
structure definition.

## Pointer Provenance and Validation

The implementation distinguishes pointer classes before interpreting any
32-bit value as an address. This is essential because an operand union, a
descriptor word, and a handler field are all four bytes wide but represent
different address spaces and lifetimes.

| Pointer class | Example | Validation and use |
|---|---|---|
| Loader code | `loader_base + 0x701D0` | must be inside the loaded PE image; used for hooks and loader-handler matching |
| Zend structure | `zend_op_array *`, `zend_class_entry *` | must point to committed readable memory and pass type/count checks |
| Loader descriptor | `op_array->reserved[3]` | must be readable before any `desc[n]` access |
| Transient data | `desc[15]`, materialized `opcodes`, `literals` | must be aligned, readable, bounded, and copied immediately |
| Internal op-array pointer | jump `zend_op *`, literal `zval *` | must fall inside the corresponding opcode or literal interval |
| Process-local code pointer | `opline->handler` | used only for opcode resolution and diagnostics; never serialized as control flow |

The core interval checks are:

```c
ops_begin <= jump_pointer < ops_begin + opcode_count
lits_begin <= literal_pointer < lits_begin + literal_count
```

The byte distance must also be exactly divisible by `sizeof(zend_op)` or
`sizeof(zval)`. Only then is the pointer converted into an index.

This prevents three common interpretation errors:

1. treating an `IS_UNUSED` union value as a pointer;
2. accepting a readable address that belongs to another allocation;
3. preserving a valid pointer whose allocation will disappear before export.

The dumper therefore converts pointer identity into stable structural identity:

```text
jump zend_op *  -> opcode index
literal zval *  -> literal index
CV frame offset -> CV index and name
loader handler  -> resolved Zend opcode
```

## IDA Pro Analysis

The loader was opened in IDA with image base:

```text
0x10000000
```

The runtime code stores RVAs, not absolute IDA addresses. For example:

```text
IDA address 0x1006FF10 -> runtime RVA 0x6FF10
```

### Investigation workflow used in IDA

The useful loader functions were identified from data flow and structure
accesses, not from guessed function names:

1. Load the DLL as a 32-bit PE and confirm image base `0x10000000`.
2. Search for repeated accesses matching known `zend_op_array` offsets,
   especially `+0x88`, `+0x34`, `+0x30`, and `+0x64`.
3. Follow cross-references from routines that write `op_array->opcodes` or
   clear the marker in `line_end`.
4. In the materializer, identify the `0x1C` stride between records. This
   confirms that the loop is walking 28-byte `zend_op` structures.
5. Trace the byte that reaches the handler-selection function. The call-site
   register state proves which byte is the real opcode.
6. Trace the selected handler into the VM dispatch loop and determine whether
   it is stored directly or transformed before execution.
7. Convert every useful virtual address into an RVA by subtracting the image
   base.
8. Record the instruction bytes overwritten by each hook and verify them at
   runtime before patching.

The decisive register states were:

| IDA location | Register or stack value | Meaning |
|---|---|---|
| `0x10002C50` | `ECX` | encoded `zend_op_array *` passed to the direct materializer |
| `0x1009BD20` | `CH` | real Zend opcode byte being materialized |
| `0x1009BD20` | `[ESP+0x2C]` | current transient `zend_op *` |
| `0x100701D0` | `ECX` | current `zend_op *` passed to the handler setter |
| `0x100701D0` | `DL` | real Zend opcode passed to the handler setter |
| `0x1006FF10` | `ECX` | `zend_execute_data *` at loader VM entry |

This register-level agreement between caller, callee, and dispatch loop is what
made the hook locations authoritative. A byte pattern alone was not treated as
sufficient evidence.

### 1. Finding the op-array restore routine

The most useful initial search was for code that simultaneously:

- reads `op_array + 0x88`;
- tests bit `0x400000` at `op_array + 0x64`;
- writes `op_array + 0x34`;
- writes `op_array + 0x30`;
- clears the `0x400000` marker.

That leads to `sub_10071660`:

```asm
10071666  mov edi, [esi+88h]             ; reserved[3]
10071677  test dword ptr [esi+64h],400000h
10071680  mov ecx, [edi+44h]             ; desc[17]
10071688  add ecx, [esi+5Ch]             ; filename pointer bits
1007168B  add ecx, dword_101B01C8         ; request key
...
100716BF  mov [esi+34h], ecx              ; op_array->opcodes
100716C2  mov eax, [edi+6Ch]              ; desc[27]
100716C5  mov [esi+30h], eax              ; op_array->last
...
100716DE  and dword ptr [esi+64h],0FFBFFFFFh
```

Equivalent simplified pseudocode:

```c
int restore_op_array(zend_op_array *oa)
{
    uint32_t *desc = oa->reserved[3];

    if (!desc || !(oa->line_end & 0x400000)) {
        return 0;
    }

    uint32_t key =
        request_key
        + (uint32_t)oa->filename
        + desc[17];

    oa->opcodes = (zend_op *)(desc[5] ^ key);
    oa->last = desc[27];
    desc[15] = adjusted_materialized_pointer;
    oa->line_end &= ~0x400000;
    return 1;
}
```

The exact byte-wise XOR is preserved by the loader code. The simplified
pseudocode shows the data relationship that mattered to the dumper.

This analysis established:

- the descriptor location;
- the encoded-state marker;
- the saved opcode count;
- the request-key global;
- the restored opcode pointer.

### 2. Finding the direct op-array materializer

`sub_10002C50`, RVA `0x2C50`, begins with:

```asm
10002C50  sub esp,14h
10002C53  mov eax,dword_101B00E0
10002C58  push ebx
10002C59  push ebp
10002C5A  push esi
10002C5B  push edi
10002C5C  mov edi,ecx
...
10002C66  mov eax,[edi+88h]               ; oa->reserved[3]
```

IDA shows:

```c
v19 = *(this + 34);       // this + 0x88
v2  = *(v19 + 76);        // desc[19]
...
v11 = (*(callback *)(v2 + 64))(this, v2);
```

The useful callable prototype is:

```c
typedef int (__fastcall *ic_step1_fn)(zend_op_array *op_array);
```

`ECX` receives the `zend_op_array *`.

Before calling this function, the extension verifies its byte signature:

```text
83 EC 14 A1 ?? ?? ?? ?? 53 55 56 57 8B F9 89 44
24 1C B9 06 00 00 00 8B 87 88 00 00 00
```

This prevents blindly calling an unexpected address if the binary does not
match the analyzed loader.

### 3. Finding where the real opcode byte exists

`sub_1009B3C0`, RVA `0x9B3C0`, builds transient `zend_op` records.

The key loop is around RVA `0x9BD20`:

```asm
1009BD20  cmp dword ptr [eax+10h],6
1009BD24  jl  short 1009BD46
...
1009BD46  mov esi,[esp+2Ch]                ; current zend_op *
1009BD4A  mov dl,ch                        ; real Zend opcode byte
1009BD4C  mov ecx,esi                      ; current zend_op *
1009BD4E  call sub_100701D0                ; install handler
...
1009BD6F  xor [esi],ecx                    ; encrypt handler pointer
1009BD72  add esi,1Ch                      ; next zend_op
```

At this point:

- `CH` contains the real opcode byte;
- `[ESP+0x2C]` contains the current `zend_op *`;
- `sub_100701D0` selects and writes the handler;
- the handler may then be XOR-transformed.

The dumper installs a hook at RVA `0x9BD20` and records:

```c
map[current_opline_pointer] = real_opcode;
```

The map uses open addressing and stores the pointer, opcode byte, and hit count.

### 4. Understanding the opcode setter

`sub_100701D0`, RVA `0x701D0`, receives:

```text
ECX = zend_op *
DL  = real Zend opcode
```

Its initial bytes are:

```text
0F B6 C2 56 57
```

IDA pseudocode:

```c
int __fastcall set_loader_opcode_handler(
    zend_op *opline,
    unsigned char opcode
) {
    if (metadata_requires_adjustment(opcode, opline)) {
        adjust_opline(opline);
    }

    void *handler = loader_handler_table[select_handler_index()];
    opline->handler = handler;
    return (int)handler;
}
```

The dumper uses this function in two ways:

1. A direct hook captures `(opline, opcode)` whenever the loader calls it.
2. It acts as an oracle for loader handlers:
   - clone the original `zend_op`;
   - try candidate opcode values `0..255`;
   - call the setter on the clone;
   - compare the generated handler with the captured handler;
   - accept the candidate when the pointers match.

Operand types are part of the cache key because handler selection may depend on
`op1_type`, `op2_type`, and `result_type`.

### 5. Understanding handler encryption

Two materializer paths can transform the selected handler pointer.

The first path is visible at:

```asm
1009BD4E  call sub_100701D0
...
1009BD6F  xor [esi],ecx
```

The second path is in `sub_10070170`:

```asm
10070184  test byte ptr [esi+4],80h
10070188  jz short real_handler_path
...
100701AF  xor edx,[eax+ecx*4]
100701B2  mov [edi],edx
...
real_handler_path:
100701C1  mov eax,[eax+ecx*4]
100701C4  mov [edi],eax
```

During deliberate materialization, the extension neutralizes both encryption
sites:

```text
RVA 0x9BD6F: 31 0E -> 90 90
RVA 0x70188: 74 2F -> EB 2F
```

This leaves the real handler pointer in the transient opcode buffer.

The patch is safe for this workflow because encoded function bodies are skipped
while materialization mode is active. The patched handler is captured, not
executed as application code.

### 6. Finding the loader VM loop

`sub_1006FF10`, RVA `0x6FF10`, is the loader's opcode dispatch loop.

Important IDA pseudocode:

```c
op_array = execute_data->func;
desc = op_array->reserved[3];

current = desc[15] ? desc[15] : op_array->opcodes;

for (;;) {
    index = (current - op_array->opcodes) / 28;
    handler = current->handler;

    if (descriptor_metadata_requires_xor) {
        uint8_t key = key_stream[index];
        handler ^= key * 0x01010101;
    }

    result = handler(execute_data);
    ...
}
```

The real code contains:

```asm
1006FF21  mov ebp,[ebx+0Ch]                ; execute_data->func
1006FF24  mov ecx,[ebp+88h]                ; reserved[3]
...
1006FF7E  xor eax,eax
1006FF90  ...                              ; / 28 -> opcode index
1006FF92  mov edx,[current_opline]          ; handler
...
1006FFF0  call edx                          ; dispatch handler
```

This proved three important facts:

1. Encoded functions are dispatched through a loader-owned VM loop.
2. The handler pointer, not the stored opcode byte, controls execution.
3. The materialized opcode array is valid at VM-loop entry.

The extension detours this entry. For an ordinary protected function, when
materialization mode is active, the hook:

1. receives `zend_execute_data *` in `ECX`;
2. obtains `execute_data->func`;
3. obtains the real opcode pointer from `desc[15]` when present;
4. obtains the opcode count from `op_array->last` or `desc[27]`;
5. deep-copies the op-array body;
6. returns `-1` immediately.

No opcode from the target function body is executed during this ordinary
capture path. Dynamic-key providers are a deliberate exception: the provider
must run so the loader can obtain the key. The target remains scoped separately
and is captured as soon as its real body becomes available.

### 7. Request-key global

The per-request key is stored at:

```text
dword_101B01C8
RVA 0xB01C8
```

IDA has multiple data references to it, including the restore routine at
`0x1007168B`.

The extension does not hard-code an absolute address. It reads:

```c
uint32_t request_key =
    *(uint32_t *)(loader_base + 0xB01C8);
```

## Hook Installation

Hooks are installed during `PHP_MINIT_FUNCTION(opcodedump)`.

The main hooks are:

| Hook | RVA | Purpose |
|---|---:|---|
| Descriptor preprocessing | `0x6CE45` | observe module function/class entries |
| Materializer opcode loop | `0x9BD20` | capture `(zend_op *, real opcode)` |
| Direct opcode setter | `0x701D0` | capture setter calls and provide handler oracle |
| Loader VM loop | `0x6FF10` | snapshot a fully materialized function and skip its body |

Hook installation follows this pattern:

```c
VirtualProtect(target, length, PAGE_EXECUTE_READWRITE, &old_protect);
save_original_bytes();
write_relative_jmp_to_hook();
FlushInstructionCache(GetCurrentProcess(), target, length);
VirtualProtect(target, length, old_protect, &tmp);
```

The opcode capture and setter hooks verify their expected bytes before patching.

The hook stubs preserve machine state with:

```asm
pushfd
pushad
...
popad
popfd
```

After capture, they execute relocated original instructions and jump back after
the overwritten bytes.

## Materializing `{main}`

The top-level op-array cannot be invoked with `zend_call_function()`.

The dumper therefore uses the direct materializer:

```c
ic_static_materialize_op_array_snapshot(op_array);
```

The exact sequence is:

1. Confirm that the op-array looks encoded:
   - user function/op-array;
   - readable `reserved[3]`;
   - odd/sentinel opcode pointer or marker bits in `line_end`.
2. Verify the `sub_10002C50` byte signature.
3. Register a snapshot entry.
4. Copy the entire original `zend_op_array` structure.
5. Call the loader materializer with the op-array in `ECX`.
6. Read the materialized opcode pointer:
   - prefer `desc[15]` when it is aligned and readable;
   - otherwise use `op_array->opcodes`.
7. Read the opcode count:
   - prefer `op_array->last`;
   - use `desc[27]` when `last` is zero.
8. Temporarily point the op-array at the materialized body.
9. Deep-copy and rebase the body.
10. Restore the original `zend_op_array` byte-for-byte.

This prevents the dumper from leaving `{main}` in a modified state.

## Materializing Class Methods

Class methods are not stored in `CG(function_table)`. They are stored in each
class entry:

```c
zend_class_entry->function_table
```

The dumper walks both class tables:

```c
CG(class_table)
EG(class_table)
```

For every `ZEND_USER_CLASS`, it walks:

```c
ZEND_HASH_FOREACH_PTR(&ce->function_table, zif)
```

For every `ZEND_USER_FUNCTION`, it calls:

```c
ic_static_materialize_op_array_snapshot(&zif->op_array);
```

This is why a class containing many methods can be fully dumped even when
`{main}` contains only `ZEND_DECLARE_CLASS` and `ZEND_RETURN`.

It also avoids constructing an object or calling a non-static method merely to
reach the loader.

## Materializing Global Functions

Global user functions are collected from:

```c
CG(function_table)
```

The pointers are copied into a temporary list before any calls are made. This
avoids invalidating a hash-table iterator if the runtime changes state.

The dumper first sends ordinary protected functions through the direct loader
materializer. Any unresolved function is then driven through
`zend_call_function()` with a synthetic call frame. `NULL` arguments are
allocated according to the function signature, with a hard safety limit of
`4096`. The function handler is set directly to the encoded `zend_function`.

For ordinary protected functions, the VM-loop hook snapshots the materialized
op-array and returns before the first target opcode executes. Dynamic-key
functions require the scoped fallback described below.

## Dynamic-Key-Protected Global Functions

ionCube dynamic-key protection delays decryption of a target function until a
user-defined provider returns the expected key. For example, the included test
fixture uses:

```php
$licenseSalt = 'CLIENT_ABC_2026';

function dk()
{
    global $licenseSalt;
    return hash('sha256', $licenseSalt);
}

// @ioncube.dynamickey dk() -> "..." RANDOM
function premiumFeature()
{
    echo "Dynamic Key function executed successfully";
}
```

The old global VM-loop policy skipped every encoded function while capture was
active. That also skipped `dk()`, so the loader never received a key and the
target body could not be materialized. The direct materializer alone cannot
solve this case because the key exists only at runtime.

The resolved path is target-scoped:

1. `{main}` is materialized first. Simple top-level `CV = CONST` assignments are
   temporarily seeded into `EG(symbol_table)`, allowing providers that use
   `global` variables to observe the same scalar setup as the source file.
2. Handler encryption patches are restored before runtime dispatch. A provider
   must execute through the loader's normal handler path.
3. `opcodedump_dynkey_capture_target` identifies the one op-array being
   collected. The VM hook passes through any different encoded function, so a
   provider such as `dk()` can execute and return the key.
4. If the target is still lazy at VM-loop entry, the hook allows the loader's
   dynamic-key materialization path to continue instead of saving an incomplete
   op-array.
5. The loader-specific `op_array + 0x38` static-variables field is temporarily
   pointed at a safe aligned dummy while the lazy path runs. This avoids a null
   or encoded `MAP_PTR` dereference before the VM-loop capture point.
6. Once materialization has populated the op-array, the dumper prefers the
   aligned `op_array->opcodes` pointer and uses `desc[15]` only as a fallback.
   The opcode count comes from `op_array->last`, or `desc[27]` when necessary.
7. A post-call and post-bailout fallback snapshots functions that became valid
   after the first hook entry.
8. The original op-array, the `+0x38` field, seeded globals, handler patches,
   exceptions, and synthetic arguments are restored or released on every path.

### IDA-verified dynamic-key path

The following locations were verified against the bundled PHP 8.1 loader whose
SHA-256 is recorded in Runtime Setup:

| IDA VA | RVA | Function/instruction | Observed role |
|---:|---:|---|---|
| `0x10002C50` | `0x2C50` | `sub_10002C50` | direct op-array materializer and dynamic-key gate |
| `0x10002C71` | `0x2C71` | `mov esi,[eax+4Ch]` | loads the per-function record from `desc[19]` |
| `0x10002CB9` | `0x2CB9` | `cmp byte ptr [esi+18h],0` | tests the dynamic-key marker at `record + 0x18` |
| `0x10002CF5` | `0x2CF5` | `call sub_10003860` | enters the dynamic-key preparation/resolution branch |
| `0x10002D71` | `0x2D71` | `mov byte ptr [esi+18h],0` | clears the marker after successful key processing |
| `0x10002DC5` | `0x2DC5` | `mov eax,[esi+40h]` / `call eax` | invokes the record's final materialization callback |
| `0x10071660` | `0x71660` | `sub_10071660` | restores `opcodes`, `last`, and `desc[15]` from the loader descriptor |
| `0x10071750` | `0x71750` | `sub_10071750` | lazy execution wrapper around materialization, restore, static variables, and VM entry |
| `0x1006FF10` | `0x6FF10` | `sub_1006FF10` | loader VM-loop entry used by the capture hook |

`sub_10071750` confirms the ordering that matters to the fix. It checks the odd
or sentinel `op_array->opcodes` value, calls `sub_10002C50`, then calls
`sub_10071660`. Before entering `sub_1006FF10`, it reads the static-variables
field at `op_array + 0x38` and follows either the direct pointer or `MAP_PTR`
path. This is why the dumper must install a temporary valid `+0x38` value before
driving a dynamic-key target and restore it afterward.

Inside `sub_10002C50`, the record is reached through
`op_array->reserved[3] -> desc[19]`. The byte at `record + 0x18` selects the
additional dynamic-key branch; after that branch succeeds, the loader clears
the byte and calls the callback stored at `record + 0x40`. These observations
are the loader-side basis for `ic_op_array_has_dynkey_encrypted_body()` and the
runtime fallback.

The main implementation points are:

| Function/state | Role |
|---|---|
| `ic_op_array_has_dynkey_encrypted_body()` | detects the dynamic-key marker reached through `desc[19]` |
| `ic_seed_simple_main_assignments()` | temporarily recreates simple top-level scalar globals |
| `opcodedump_dynkey_capture_target` | separates the protected target from helper/provider calls |
| `ic_vm_loop_should_skip_and_capture()` | captures a ready target or passes through a provider/lazy target |
| `ic_dynkey_post_materialize_snapshot()` | copies a target that became readable after lazy materialization |
| `ic_runtime_materialize_all_functions()` | coordinates direct capture, runtime fallback, and cleanup |

`dynamic_protected_encoded.php` is the regression fixture for this path. Its
dump contains the top-level assignment and call, the complete `dk()` provider
(`ZEND_BIND_GLOBAL` and the `hash()` call), and the complete
`premiumFeature()` body (`ZEND_ECHO`, `ZEND_RETURN`).

Dynamic-key capture necessarily executes the key provider. A provider with
external side effects can therefore produce those side effects during a dump.
The protected target is skipped once its materialized body reaches the capture
hook. Providers that depend on complex top-level execution, external services,
or unavailable request state may still require an environment-specific setup.

## Stabilizing Transient Memory

The loader's materialized `opcodes` and `literals` arrays are transient.
Keeping only their pointers would produce use-after-free reads during JSON
serialization.

`ic_deep_copy_op_array_body()` performs a structural snapshot:

```c
new_lits = malloc(last_literal * sizeof(zval));
memcpy(new_lits, old_lits, ...);

new_ops = malloc(last * sizeof(zend_op));
memcpy(new_ops, old_ops, ...);
```

Because this is an x86 build:

```c
ZEND_USE_ABS_JMP_ADDR   == 1
ZEND_USE_ABS_CONST_ADDR == 1
```

Jump operands and literal operands contain absolute pointers. Every copied
operand is inspected and rebased:

```c
if (pointer is inside old opcode array) {
    pointer = new_opcode_base + (pointer - old_opcode_base);
}

if (pointer is inside old literal array) {
    pointer = new_literal_base + (pointer - old_literal_base);
}
```

Without this step, the copied opcode array would still point back into freed
loader memory.

The snapshot entry is matched later by:

- original `zend_op_array *`;
- `desc[19]`;
- function name plus scope.

## Recovering the Real Opcode

The C extension does not trust `opline->opcode` by itself.

For every opcode, the resolution order is:

1. `zend_op_data_pseudo`
2. opcode captured while the loader materialized the current opline
3. opcode recovered from a native Zend VM handler
4. opcode recovered from a loader handler
5. raw opcode byte as a last mechanical fallback

The JSON records the source:

```json
"resolved_opcode_source": "zend_vm_handler"
```

or:

```json
"resolved_opcode_source": "ioncube_loader_handler"
```

### Native Zend handler matching

For a handler that points into PHP's VM:

```c
for (opcode = 0; opcode <= 255; opcode++) {
    probe = copy_of_original_opline;
    probe.opcode = opcode;
    probe.handler = NULL;
    zend_vm_set_opcode_handler(&probe);

    if (probe.handler == captured_handler) {
        return opcode;
    }
}
```

The next opline is copied into a two-opcode probe buffer because handler
selection for some opcodes depends on an adjacent `ZEND_OP_DATA`.

### Loader handler matching

For a handler inside the loader image:

```c
for (opcode = 0; opcode <= 255; opcode++) {
    probe = copy_of_original_opline;
    probe.opcode = opcode;
    probe.handler = NULL;
    loader_opcode_setter(&probe, opcode);

    if (probe.handler == captured_handler) {
        return opcode;
    }
}
```

Results are cached by:

```text
(handler, op1_type, op2_type, result_type)
```

### Exact `ZEND_OP_DATA` recognition

`ZEND_OP_DATA` is preserved only when its structure matches the Zend pairing
rule:

- current raw opcode is `ZEND_OP_DATA`;
- `op2_type` and `result_type` are `IS_UNUSED`;
- `op1_type` is a valid operand type;
- the previous real opcode is one that consumes `ZEND_OP_DATA`.

The consumer list includes assignment forms such as:

```text
ZEND_ASSIGN_DIM
ZEND_ASSIGN_OBJ
ZEND_ASSIGN_STATIC_PROP
ZEND_ASSIGN_DIM_OP
ZEND_ASSIGN_OBJ_OP
ZEND_ASSIGN_STATIC_PROP_OP
ZEND_ASSIGN_OBJ_REF
ZEND_ASSIGN_STATIC_PROP_REF
```

This avoids interpreting an opcode as `OP_DATA` solely because a byte happens
to equal its numeric value.

### Optional semantic IR fallback

`lib/ir.php` contains a presentation fallback for opcodes that still have no
authoritative mechanical resolution. It may classify a small set of unresolved
operators from operand and branch context.

It does not overwrite these authoritative sources:

```text
ioncube_materializer_capture
ioncube_loader_handler
zend_vm_handler
zend_op_data_pseudo
ioncube_xor_key
zend_opcode
```

To disable the optional IR fallback completely:

```bat
set OPCODEDUMP_DISABLE_SEMANTIC_OPCODE_RESOLVE=1
dump.bat sample.php
```

The loader capture, handler matching, operands, and jump targets are independent
of this presentation fallback.

## Literal Recovery

For `IS_CONST`, the union contains a `zval *`.

The dumper validates that the pointer is inside:

```text
[op_array->literals,
 op_array->literals + op_array->last_literal)
```

The stable literal index is:

```c
literal_index = operand.zv - op_array->literals;
```

The JSON retains:

- literal index;
- Zend value type;
- printable value or preview;
- length;
- hexadecimal bytes;
- Base64.

Keeping the raw byte representations is important for binary strings and
obfuscated identifiers that are not valid printable text.

## CV Variable Recovery

An `IS_CV` operand stores a byte offset into the call frame.

The CV index is:

```c
cv_slot  = operand.var / sizeof(zval);
cv_index = cv_slot - ZEND_CALL_FRAME_SLOT;
```

The name is then read from:

```c
op_array->vars[cv_index]
```

If the original name is not printable, the dumper creates a stable reversible
display name:

```text
_obfuscated_<HEX_BYTES>_
```

This changes only the display representation. The operand slot and raw bytes
remain available.

## Exact Jump Target Recovery

Jump target recovery is based on Zend operand semantics and pointer arithmetic.
It is not based on guessing source constructs such as `if`, `while`, or
`foreach`.

On this x86 runtime, a normal jump operand contains an absolute `zend_op *`.

The target index is:

```c
target_index =
    ((uintptr_t)target_pointer - (uintptr_t)op_array->opcodes)
    / sizeof(zend_op);
```

The pointer is accepted only when:

```text
opcodes_base <= target < opcodes_base + last
```

and:

```text
(target - opcodes_base) % sizeof(zend_op) == 0
```

### Operand containing the target

| Opcode family | Target location |
|---|---|
| `ZEND_JMP` | `op1` |
| `ZEND_FAST_CALL` | `op1` |
| `ZEND_JMPZ` | `op2` |
| `ZEND_JMPNZ` | `op2` |
| `ZEND_JMPZNZ` | `op2` plus `extended_value` |
| `ZEND_JMPZ_EX` | `op2` |
| `ZEND_JMPNZ_EX` | `op2` |
| `ZEND_FE_RESET_R/RW` | `op2` |
| `ZEND_JMP_SET` | `op2` |
| `ZEND_COALESCE` | `op2` |
| `ZEND_ASSERT_CHECK` | `op2` |
| non-final `ZEND_CATCH` | `op2` |
| `ZEND_FE_FETCH_R/RW` | `extended_value` |

### `ZEND_JMPZNZ`

`ZEND_JMPZNZ` has two destinations:

- `op2` contains one branch target;
- `extended_value` contains the second absolute opline pointer.

The second target is exported separately:

```json
"jmpznz_true_opline": 42
```

Both destinations are included in `jump_targets`.

### `foreach`

`ZEND_FE_RESET_R/RW` contains the initial empty-iterator exit target in `op2`.

`ZEND_FE_FETCH_R/RW` uses `extended_value` for the done target. Its `op2` is a
value destination and must not be interpreted as a jump.

The dumper exports:

```json
"fe_fetch_done_opline": 197
```

This distinction prevents a variable slot from becoming a bogus CFG edge.

### Final `ZEND_CATCH`

The VM definition uses:

```text
ZEND_CATCH: op1=CONST, op2=JMP_ADDR, extended=LAST_CATCH|CACHE_SLOT
```

When `extended_value & ZEND_LAST_CATCH` is nonzero, there is no next catch.
`op2` may contain zero, but zero is not a jump to opcode zero.

The exact rule is:

```c
if (opcode == ZEND_CATCH &&
    operand_index == 2 &&
    (opline->extended_value & ZEND_LAST_CATCH)) {
    return not_a_jump_target;
}
```

Example from the generated dump:

```json
{
    "index": 133,
    "opcode_name": "ZEND_CATCH",
    "extended_value_decoded": {
        "is_last_catch": true
    },
    "op2": {
        "type_name": "IS_UNUSED",
        "opline_num": 0
    },
    "jump_targets": []
}
```

### Loader branch-target unshuffle

Some materialized branches initially point to a shuffled target index.

The decoder uses descriptor data rather than source-level pattern matching:

```text
context   = descriptor + 0x1C
shuffle A = desc[25]
shuffle B = desc[26]
```

For one branch:

1. Convert the current target pointer to an opcode index.
2. Read `current_shuffle = shuffle_a[current_index]`.
3. Calculate `pivot_index = current_index - current_shuffle`.
4. Select the valid range before or after the pivot.
5. Read context words `c0..c3` and indirect words `p4..p7`.
6. Calculate:

```c
denom =
    p5 + p4 + c3 + c2 + c0 + c1 + p6 + 17;

step =
    p6 + p5 + p4 + c3 + c2 + c1 + c0
    + (p7 % denom);

step %= window_length;
if (step == 0) {
    step = 1;
}
```

7. Subtract `step` from the shuffled index and wrap inside the selected range.
8. Apply the optional post-shuffle entry from `shuffle_b`.
9. Replace the operand with:

```c
copy->opcodes + decoded_index
```

10. Mark the opline with bit `0x200000` so it is not decoded twice.

The marker bits are removed from exported source-line fields.

## Building the Control-Flow Graph

`lib/ir.php` builds the CFG from the recovered target indexes.

Block leaders are:

- opcode zero;
- every valid jump target;
- the opcode immediately after an opcode that has a jump target.

Each block contains:

```json
{
    "id": "B3",
    "start": 12,
    "end": 26
}
```

Edges are:

- `jump` for every explicit recovered target;
- `fallthrough` when the block terminator can continue to the next opcode.

No fallthrough edge is created after:

```text
ZEND_JMP
ZEND_RETURN
ZEND_THROW
ZEND_EXIT
```

Because CFG construction consumes the same `jump_targets` exported for each
opcode, target validation and CFG validation check the same underlying data.

## Raw Export and IR Export

### C-extension layer

`dasm_file()`:

1. compiles the requested file;
2. materializes `{main}`;
3. materializes class methods;
4. drives global functions through the VM capture path;
5. selects stable snapshots;
6. exports the main op-array;
7. exports function and class tables;
8. exports optional ionCube internal-call observations.

`dasm_zend_op_array()` exports:

- function identity and scope;
- flags and argument information;
- literals;
- opcode records;
- variables;
- live ranges;
- try/catch data;
- static variables;
- filename and line metadata.

`dasm_zend_op()` exports:

- raw and resolved opcode;
- resolution source;
- operand types;
- literal references;
- CV names;
- stable target indexes;
- handler address and loader-relative RVA when applicable;
- special target fields such as `jmpznz_true_opline`.

### PHP normalization layer

`normalize.php`:

- canonicalizes malformed or truncated raw keys;
- filters synthetic helper classes;
- filters unrelated functions by source path;
- creates a stable key order for the TXT output.

### IR layer

`ir.php`:

- converts values into safe JSON records;
- creates stable op-array identifiers;
- maps CV slots to names;
- builds `jump_targets`;
- decodes function and extended-value flags;
- creates literal cross-references;
- builds the CFG;
- creates decompilation-oriented site indexes.

`analysis.sites` copies already-normalized IR operands directly. It does not
reparse an IR opcode as if it were a raw extension opcode.

## JSON Example

A branch entry has this general form:

```json
{
    "index": 4,
    "line": 2,
    "opcode": 43,
    "opcode_name": "ZEND_JMPZ",
    "op1": {
        "type": 4,
        "type_name": "IS_VAR",
        "var": 208
    },
    "op2": {
        "type": 0,
        "type_name": "IS_UNUSED",
        "opline_num": 136
    },
    "jump_targets": [
        136
    ],
    "resolved_opcode_source": "zend_vm_handler"
}
```

The important reconstruction facts are:

- the opline at index 4 evaluates a condition in `op1`;
- the false branch goes to opcode 136;
- the true path falls through to opcode 5;
- the target is an index inside the same op-array.

## Memory Safety Measures

Loader-owned memory is treated as untrusted and potentially transient.

The extension uses:

- `VirtualQuery()` to require committed readable pages;
- strict pointer alignment checks;
- strict opcode/literal/count upper bounds;
- `__try/__except` around loader memory reads;
- `zend_try/zend_catch` around engine calls;
- temporary `VirtualProtect()` only while reading protected arrays or patching
  known hook sites;
- byte-signature checks before calling or patching critical loader routines;
- per-op-array snapshots so serialization never depends on transient buffers;
- restoration of the original op-array after direct materialization.

If full opcode decoding throws a structured exception, a minimal record is
emitted with:

```json
"decode_failed": true
```

This prevents one unreadable opline from aborting the entire file dump.

## Validation Method

The dumper was validated by compiling known plaintext PHP through normal Zend
compilation with the same PHP runtime and comparing it with the encoded dump.

The comparison process is:

1. Match op-arrays by function name and class scope.
2. Compare argument counts and required argument counts.
3. Compare CV counts and names.
4. Compare literal arrays.
5. Compare opcode counts.
6. Compare opcode names in order.
7. Compare operand types.
8. Compare meaningful operand values.
9. Ignore numeric union values for `IS_UNUSED`.
10. Compare every jump source and target.
11. Compare CFG blocks and edges.
12. Ignore raw handler addresses because ASLR changes them between processes.

One detailed method comparison produced:

```text
encoded opcodes:        200
plaintext opcodes:      200
canonical matches:      200/200
encoded jump targets:   14
plaintext jump targets: 14
target differences:     0
CFG differences:        0
literal differences:    0
operand-type differences: 0
```

The only raw opcode-name differences were call-finalization forms emitted by
the loader versus the normal compiler. They had identical operands, result
slots, surrounding call setup, control flow, and source semantics.

A larger function-set comparison established:

```text
matched op-arrays: 179/179
encoded branches:  716
plaintext branches: 716
invalid targets:   0
```

The current `sample.php` dump validates as:

```text
op-arrays:        11
classes:          1
methods:          10
opcodes:          1217
jump targets:     64
invalid targets:  0
unknown opcodes:  0
decode failures:  0
```

## Automated Target Validation

This PowerShell check verifies that every target is inside its own op-array:

```powershell
$j = Get-Content -Raw .\sample.opcodes.json | ConvertFrom-Json
$invalid = @()

foreach ($property in $j.op_arrays.PSObject.Properties) {
    $opArray = $property.Value
    $count = @($opArray.opcodes).Count

    foreach ($opcode in $opArray.opcodes) {
        foreach ($target in @($opcode.jump_targets)) {
            if ([int]$target -lt 0 -or [int]$target -ge $count) {
                $invalid += [pscustomobject]@{
                    op_array = $property.Name
                    source   = $opcode.index
                    target   = $target
                    count    = $count
                }
            }
        }
    }
}

$invalid
```

An empty result means that every exported target is in range.

## Environment Variables

| Variable | Purpose |
|---|---|
| `OPCODEDUMP_RUNTIME_MATERIALIZE=1` | materialize `{main}`, methods, and functions |
| `OPCODEDUMP_MATERIALIZE_MAIN=1` | materialize `{main}` directly |
| `OPCODEDUMP_DISABLE_MAIN_MATERIALIZE=1` | skip direct `{main}` materialization |
| `OPCODEDUMP_DISABLE_VM_LOOP_HOOK=1` | disable VM-entry snapshot hook |
| `OPCODEDUMP_DISABLE_OPCODE_CAPTURE_HOOK=1` | disable capture at RVA `0x9BD20` |
| `OPCODEDUMP_DISABLE_OPCODE_SETTER_HOOK=1` | disable setter hook at RVA `0x701D0` |
| `OPCODEDUMP_CAPTURE_DESCRIPTOR_DUMP=1` | export descriptor-observed entries |
| `OPCODEDUMP_CAPTURE_ALL_INTERNAL=1` | record all internal calls, not only ionCube APIs |
| `OPCODEDUMP_CAPTURE_FILE=<path>` | identify a target file in internal-call logging |
| `OPCODEDUMP_OUTPUT_DIR=<path>` | redirect JSON and TXT outputs |
| `OPCODEDUMP_DISABLE_SEMANTIC_OPCODE_RESOLVE=1` | disable optional IR-only semantic fallback |
| `OPCODEDUMP_DISABLE_AUTODEFINE_OPENCART_DIRS=1` | disable automatic OpenCart directory constants |

`dump.bat` enables:

```bat
set OPCODEDUMP_RUNTIME_MATERIALIZE=1
```

`OPCODEDUMP_OUTPUT_DIR` is honored by the PHP output layer. The current
`dump.bat` completion check still looks next to the input file, so use the PHP
entry point directly when redirecting output:

```bat
runtime\php.exe -c runtime\php.ini opcodedump.php sample.php
```

## Important Interpretation Rules

1. `resolved_opcode_source` explains why an opcode name was selected.
2. `handler` is process-specific and must not be compared across processes.
   The raw TXT layer may contain `handler_rva` for loader-owned handlers, but
   it is diagnostic and meaningful only for the analyzed loader binary. The
   JSON IR does not currently propagate that field.
3. Values inside an `IS_UNUSED` operand are not source-level values.
4. `jump_targets` contains stable opcode indexes, not raw pointers.
5. `ZEND_CATCH` with `is_last_catch=true` has no next-catch target.
6. `ZEND_FE_FETCH_R/RW` takes its completion target from `extended_value`.
7. A small `{main}` does not imply missing class methods.
8. JSON is the authoritative reconstruction-oriented format.
9. Line numbers may be absent or zero without affecting opcode or CFG accuracy.
10. Source reconstruction must follow operand types, result slots, literal
    references, and CFG together; opcode names alone are insufficient.

## Loader-Specific Maintenance

The loader RVAs and instruction signatures are part of the implementation
contract. Before using a different loader binary:

1. load it into IDA;
2. verify image base and architecture;
3. locate the op-array restore routine through the `+0x88`, `+0x64`, `+0x34`,
   and `+0x30` accesses;
4. locate the materializer that reads `reserved[3]`;
5. locate the loop where the real opcode is passed to the handler setter;
6. locate all handler-encryption paths;
7. locate the VM dispatch loop;
8. verify every hook signature and overwritten instruction;
9. repeat plaintext-versus-encoded control-flow validation.

Do not update an RVA merely because a nearby byte pattern looks similar. The
calling convention, register roles, structure offsets, and post-hook control
flow must all match.

## Core Source References

- Loader constants and descriptor support:
  `src/opcodedump.c`
- Handler-to-opcode recovery:
  `zend_vm_handler_opcode_from_opline()` and
  `ic_loader_handler_opcode_from_opline()`
- Stable snapshots:
  `ic_deep_copy_op_array_body()` and
  `ic_dynamic_save_entry_copy()`
- Direct materialization:
  `ic_static_materialize_op_array_snapshot()`
- Class method capture:
  `ic_static_materialize_all_class_methods()`
- Runtime function capture:
  `ic_runtime_materialize_all_functions()`
- Dynamic-key detection and post-materialization capture:
  `ic_op_array_has_dynkey_encrypted_body()` and
  `ic_dynkey_post_materialize_snapshot()`
- Dynamic-key provider state:
  `ic_seed_simple_main_assignments()` and
  `ic_seeded_global_state_restore()`
- VM-loop snapshot:
  `ic_vm_loop_should_skip_and_capture()` and
  `ic_runtime_capture_execute_data()`
- Jump conversion:
  `dasm_jump_target_index()` and `opcode_jump_targets()`
- Raw op-array export:
  `dasm_zend_op_array()`
- JSON IR and CFG:
  `lib/ir.php`

## Summary

The dumper succeeds because it follows the loader's real runtime data flow:

```text
descriptor
  -> materialized op-array
  -> real opcode passed to handler setter
  -> real handler selected
  -> VM dispatch entry
  -> transient opcode/literal buffers
  -> stable rebased snapshot
  -> exact operand and target indexes
  -> JSON IR and CFG
```

The resulting dump is suitable as the low-level input for PHP code
reconstruction because it preserves the information that defines execution:
opcode order, operand types, literals, CV slots, temporary slots, exception
metadata, and exact control-flow destinations.
