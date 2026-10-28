# Resident named-export guest profile — RC6 candidate

This is a guest-only metadata/API model, not a Windows/Wine installation.
Nine declared resident DLL views (user32, gdi32, comdlg32, shell32, shlwapi,
comctl32, msvcrt, version, mscoree) have mapped PE32 bases, named exports and loader rings.
Core kernel32/KernelBase/ntdll keep the existing bundled guest images. No native
DLL initialization, host loader, network request or external LLM call is used.
Names come from public Wine commit fd1153552d779e1ac14b0b1c48fbd1cde894eb0a;
only identifier metadata is embedded. No Wine implementation is compiled/run.

Callable export markers use bounded IDs and survive five/eight-byte guest copies.
Actual Unicorn tests cover stdcall, cdecl, a guest interposition JMP and scheduled
CRT initializer callbacks. Unsupported API execution stops explicitly. Unknown
markers cannot return stale EAX. The pinned Unicorn 1.x invalid-instruction
code-hook behavior is a tested compatibility requirement. API dispatch is capped
at 65,536 calls. Metadata is R/NX, code RX and data RW/NX; VirtualProtect uses actual
modeled reservations and Unicorn page enforcement. Protection modifiers outside
the existing private-page profile remain unsupported.

Model-local ordinal indices are not Windows ordinal contracts. Native ordinal
requests, forwarders, resources, TLS and general unloading remain unsupported.
A known function's presence in an export directory does not establish execution
support. _acmdln, _adjust_fdiv, __initenv and __winitenv have real data cells.
CRT startup initializes the narrow empty-environment vector; host environment
variables are never copied. DLL views are explicitly pinned resident objects, not
asserted normal process startup. This mixed metadata profile is not a Windows 7 ABI.

Missing modules and absent named exports return NULL/error in the configured
namespace. They never get fake successful handles or import bindings. Known data
without modeled storage remains unsupported. LoadLibrary success increments a
separate model reference count; GetModuleHandle does not. FreeLibrary cannot drop
a pinned image's reference floor. Native DLL code is never invoked.

Observation epochs remain separate from OS reference counts. Retained-bound-table
recovery requires complete validated descriptors and unambiguous pointer identities.
It can correlate one whole application lookup epoch without merging an earlier
loader epoch into that table. A subset of a single epoch is still rejected. All
unrepresented epochs remain in evidence. Original programs never select or build
output. The seven acceptance gates (executable bytes, OEP RVA/mapping, imports,
IAT readiness, descriptor termination and machine) are unchanged.

The candidate default is --guest-module-profile named-exports; core-strict is an
explicit alternative. Decode60/job75/output32MiB and the existing Bubblewrap
isolation remain enforced. Partial/unsupported/timeout/failed are unsuccessful
recovery outcomes. Static gates do not establish full behavior or devirtualization.
The RC4 and frozen RC5 v4 baselines must remain until a final single-wheel corpus
preserves all 33 accepted rows. RC6 v1 regressed to31 and is frozen/rejected.

## Primary semantic references

- [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress): failed lookup returns NULL; names are case sensitive.
- [LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya): missing-module failure returns NULL; successful loads change reference counts.
- [Internal CRT globals](https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions): globals are version-dependent implementation details.
- [Pinned Wine data declarations](https://github.com/wine-mirror/wine/blob/fd1153552d779e1ac14b0b1c48fbd1cde894eb0a/dlls/msvcrt/data.c): initial environment pointer cells are data with initial NULL state.


RC6 v3 includes callable-name metadata for thiscall/stub declarations. The
mscoree view supplies named CLR entry metadata only; actual CLR entry execution
remains unsupported. Bounded wsprintfA supports ANSI strings, characters and
PE32 integers with a 1024-byte output/32-argument limit and cdecl ownership.
Wide, floating, writeback and other unsupported formats stop before output writes.
[Microsoft wsprintfA contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-wsprintfa).

Importless generic attempts stop before section/checksum/file serialization.
They remain rejected in the existing 1024-key and decode60s bounds; the 64 actual
candidate-image limit is unchanged. No importless dump can become accepted.
Intentional API-model stops report the API semantic cause, even if Unicorn also
reports an invalid instruction at the dispatch marker.


The negative-cache experiment is retained separately and excluded from this
candidate: the real Molebox run had191 skipped importless attempts and zero
cache hits. Empty/null-descriptor early rejection remains. wvsprintfA passes a
guest va_list to the same bounded formatter, with its documented stdcall cleanup.
