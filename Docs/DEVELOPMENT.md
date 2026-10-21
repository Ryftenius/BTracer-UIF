# Developer guide

## Build and test

Use PowerShell 7, Visual Studio's C++ toolset and the Windows SDK. Build the
VCXProj projects with Configuration=Release and Platform=x64 or Win32. Product
version 1.0.1 and SDK version 0.3 are separate from packet protocol version 3.
Override the runner version with /p:SkuggaVersion=x.y.z.

Release uses /O2, whole-program optimization and /LTCG, /OPT:REF, /OPT:ICF,
NDEBUG, stack cookies, ASLR and NX. CFG is enabled where supported; selected
native hook translation units retain explicit per-file CFG/LTO exceptions.
The build does not require AVX2. This is not full-module CFG coverage.

```powershell
msbuild VCXProj\SKUGGA.vcxproj /p:Configuration=Release /p:Platform=x64 /m
msbuild VCXProj\SkuggaRunner.vcxproj /p:Configuration=Release /p:Platform=x64 /m
msbuild VCXProj\SkuggaTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64 /m
msbuild VCXProj\SkuggaSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64 /m
.\Scripts\test_cli_syntax.ps1 -BinaryPath .\bin\Release\x64\SkuggaRunner.exe
.\Scripts\test_internal_telemetry.ps1
```

Format C/C++ using clang-format -i -style=file; check with --dry-run --Werror.
The root .clang-format supplies the project style. Deploy the runner as skugga.exe
or sk.exe beside the matching SKUGGA.dll. Preserve sibling architecture folders
for x86/x64 handoff. Keep PDBs in private symbol storage and close instrumented
targets before replacing a loaded DLL.

## CLI and diagnostics

```powershell
sk run .\owned-target.exe --api NtQueryInformationProcess --stack --symbols --timeout 10s
sk run /group:network /timeout:10s -- .\owned-target.exe /target-option
sk run .\owned-target.exe --api NtQueryInformationProcess --include-internals --debug --timeout 10s
```

--stack, --registers, --deny and --quiet apply across the command. Registers and
denial require NT-only selections. Arguments after -- belong to the target.
Quote conditions containing shell metacharacters.

--debug writes a bundle under bin/<configuration>/<platform>/SkuggaDiagnostics:

- summary.txt: status, readiness, totals and paths.
- events.jsonl: original events, including unfiltered stacks.
- selfmap.tsv: runtime-owned ranges, patches, stubs and callbacks.
- logs/: runtime initialization, lifecycle and optional captured bytes.

--include-internals controls console frames and machinery independently of
--debug. It does not disable internal-call suppression. --raw includes API events
alongside summaries without the protect-folding startup notice. Symbols need
matching PDBs on --sym-path or _NT_SYMBOL_PATH. Missing observations stay unknown.

## SDK contract

Include SDK/include/skugga/skugga_ipc.h for SKUGGA_IPC_* types/constants and
SkuggaIpc* enum values. IPC-only hosts do not link the DLL. Explicit VEH consumers
include skugga_veh.h, define IX_SKUGGA_IMPORTS and link SKUGGA.lib. Export names
remain as declared in that header.

SDK/samples/host/SkuggaSdkHost.cpp is the reference host. Create and own the target
and local pipe; load the matching runtime; handle handshake/policy queries; wait
for readiness; acknowledge requests with the same command and sequence.
Default pipe: \\.\pipe\SKUGGAHookIngest. SKUGGA_PIPE_NAME selects another;
SKUGGA_LOG_DIR selects runtime log output. SKUGGA_RUNNER_OWNS_PIPE=1 prevents
the test target from self-hosting.

Validate packet length, magic, version, type, command, event/batch counts and
fixed-string termination before formatting. ABI/packet_validation.h provides
event checks; reject malformed batches as a whole. Keep handlers bounded and
move expensive enrichment off the pipe thread. Local transport is not an
authentication boundary against other processes running as the same user.

Core readiness is SKUGGA_SDK_READY_CORE_MASK=0x0D (IPC, NT, KI); module-aware
runs may report 0x1D; full ABI readiness is 0x1F. This does not prove every API
path was intercepted. SDK hosts receive original packets and choose presentation.

Events carry PID/TID, Kind/Operation, Caller/Context0..3, Args/ArgCount,
Stack/StackCount, Status/Action and DataSample/DataSize. Integrity events with
IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY encode kind/address/size/flags in Context0..3;
Args hold references and memory attributes. Headers define exact layouts and
bounds. Pin matching headers/runtime; wire values remain versioned.

## Release

Validate both architectures before advertising both. Run packet-validation tests,
CLI tests, owned probes and host handshake checks. Verify effective build flags
and PE mitigations. Sign final DLL/EXE artifacts, then record hashes and build ID.
Test signed files. Exclude keys, private certificates, PDBs, build trees, captures
and local environment notes. Ship LICENSE and follow its distribution terms.
