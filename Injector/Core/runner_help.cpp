#include "Core/runner_help.h"

namespace skugga::injector
{
    bool IsHelpArgument(const wchar_t *arg) noexcept
    {
        return arg != nullptr && (wcscmp(arg, L"help") == 0 || wcscmp(arg, L"--help") == 0 || wcscmp(arg, L"-h") == 0 ||
                                  wcscmp(arg, L"/?") == 0);
    }

    void PrintUsage()
    {
        std::wprintf(L"Usage\n\n"
                     L"  sk run <target.exe> [options]\n"
                     L"  sk <target.exe> [options]\n"
                     L"  sk help [topic]\n"
                     L"  sk hooks | groups\n\n"
                     L"Observe\n\n"
                     L"  --api <name,list>      Observe and log selected APIs; repeatable.\n\n"
                     L"  --group <name,list>    Observe a category, such as memory or network.\n\n"
                     L"  --behavior[=areas]    Fold events into behavior summaries.\n\n"
                     L"Output and policy (apply to all selected APIs)\n\n"
                     L"  --stack               Include call stacks.\n\n"
                     L"  --registers           Include registers (NT APIs only).\n\n"
                     L"  --deny                Deny selected calls (NT APIs only).\n\n"
                     L"  --quiet               Suppress individual API events.\n\n"
                     L"  --symbols             Resolve symbols for call stacks.\n\n"
                     L"  --include-internals   Include SKUGGA frames and machinery records.\n"
                     L"                        Raw diagnostic files always retain original events.\n\n"
                     L"Execution\n\n"
                     L"  --timeout <duration>  For example 15000, 30s, or 2m.\n\n"
                     L"  --loader <method>     standard (default) or manual.\n\n"
                     L"  --no-launch-gate      Disable the pre-entry launch gate.\n\n"
                     L"  --debug               Enable diagnostics and runtime logs.\n\n"
                     L"Syntax\n\n"
                     L"  sk and skugga are equivalent executable names.\n"
                     L"  Slash forms: /api:Name, /group network, /stack, /timeout:30s.\n"
                     L"  Use -- before the target to preserve all following target arguments.\n"
                     L"  Legacy --hook/--lhook and other spellings remain accepted.\n"
                     L"  Legacy --stack-trace/--regs retain their preceding-rule scope.\n\n"
                     L"Examples\n\n"
                     L"  sk run sample.exe --group network\n\n"
                     L"  sk run sample.exe --api NtAllocateVirtualMemory --stack\n\n"
                     L"  sk run /group:network /timeout:30s -- sample.exe /target-option\n\n");
    }

    void PrintHelpTopic(const wchar_t *topic)
    {
        std::wstring key = topic != nullptr ? topic : L"";
        for (auto &ch : key)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
        if (key.empty() || key == L"help" || key == L"commands")
        {
            PrintUsage();
            return;
        }

        if (key == L"run" || key == L"cli")
        {
            PrintUsage();
            return;
        }

        if (key == L"hooks" || key == L"hook" || key == L"functions" || key == L"function")
        {
            std::wprintf(L"SKUGGA help: hooks\n\n");
            std::wprintf(L"Usage:\n\n");
            std::wprintf(L"  sk run .\\sample.exe --api NtQueryInformationProcess "
                         L"--stack\n");
            std::wprintf(L"  sk run .\\sample.exe --api "
                         L"NtAllocateVirtualMemory,NtProtectVirtualMemory,loader\n");
            std::wprintf(L"  sk run .\\sample.exe --api "
                         L"[nt:NtOpenProcess,module:CoCreateInstance,winsock:connect]\n\n");
            std::wprintf(L"Selectors\n\n");
            std::wprintf(L"  --api <name,list>      Observe APIs; repeatable.\n\n");
            std::wprintf(L"  --group <name,list>    Observe categories; repeatable.\n\n");
            std::wprintf(L"  --quiet               Suppress individual events.\n\n");
            std::wprintf(L"Prefixes:\n\n");
            std::wprintf(L"  nt:<name>              NT/native syscall-family hook.\n");
            std::wprintf(L"  module:<name>          User-mode export hook such as "
                         L"CoCreateInstance.\n");
            std::wprintf(L"  winsock:<name>         Winsock/DNS hook such as send or "
                         L"GetAddrInfoW.\n");
            std::wprintf(L"  group:<name>           Built-in group, same as "
                         L"--group.\n\n");
            std::wprintf(L"Command options\n\n");
            std::wprintf(L"  --stack, --registers, --deny, --quiet apply to all selections.\n");
            std::wprintf(L"  --registers and --deny require NT-only selections.\n\n");
            std::wprintf(L"  --include-internals restores SKUGGA frames and machinery.\n");
            std::wprintf(L"  /api:Name /group:memory /stack are equivalent slash forms.\n\n");
            return;
        }

        if (key == L"groups" || key == L"group")
        {
            std::wprintf(L"SKUGGA help: groups\n\n");
            std::wprintf(L"Core groups:\n\n");
            std::wprintf(L"  "
                         L"behavior/memory/protect/thread/process/file/token/remote/"
                         L"injection/anti-analysis\n");
            std::wprintf(L"Module groups:\n\n");
            std::wprintf(L"  "
                         L"loader/etw/amsi/http/network/crypto/credentials/sspi/vault/"
                         L"dpapi/com/jobs/cloud/exceptions\n");
            std::wprintf(L"Winsock group:\n\n");
            std::wprintf(L"  winsock covers WSASend, WSARecv, send, recv, connect, "
                         L"WSAConnect, GetAddrInfo*, and "
                         L"DnsQuery*.\n\n");
            std::wprintf(L"Examples:\n\n");
            std::wprintf(L"  sk run .\\sample.exe --group loader,anti-analysis,remote "
                         L"--stack\n");
            std::wprintf(L"  sk run .\\sample.exe --group credentials --symbols --stack\n");
            std::wprintf(L"  sk run .\\sample.exe --api "
                         L"group:network,nt:NtQueryInformationProcess\n");
            return;
        }

        if (key == L"behavior" || key == L"behaviour" || key == L"smart")
        {
            std::wprintf(L"SKUGGA help: behavior\n\n");
            std::wprintf(L"Usage:\n\n");
            std::wprintf(L"  sk run .\\sample.exe --behavior\n");
            std::wprintf(L"  sk run .\\sample.exe --behavior=all --behavior-stacks 8 "
                         L"--when rwx\n");
            std::wprintf(L"  sk run .\\sample.exe --behavior=remote --summary-interval 0\n\n");
            std::wprintf(L"Areas:\n\n");
            std::wprintf(L"  memory, protect, threads, writes, reads, queries, "
                         L"handles, apc, maps, remote, all.\n");
            std::wprintf(L"Options:\n\n");
            std::wprintf(L"  --behavior-stacks[=N|all]       Print representative "
                         L"folded stacks.\n");
            std::wprintf(L"  --behavior-protect-stacks       Capture "
                         L"protect-transition stacks.\n");
            std::wprintf(L"  --raw                           Also print raw events.\n");
            std::wprintf(L"  --summary-interval <ms>         Print live summaries; 0 "
                         L"prints final only.\n");
            std::wprintf(L"  --when <condition>              rwx, remote, "
                         L"start.private, protect.flips>=N,\n");
            std::wprintf(L"                                  thread.count>=N, "
                         L"alloc.total>NMB.\n");
            return;
        }

        std::wprintf(L"[skugga] unknown help topic: %ls\n\n", topic != nullptr ? topic : L"<null>");
        PrintUsage();
    }
    bool CopyWideToAnsi(const wchar_t *input, char *out, std::size_t outChars) noexcept
    {
        if (input == nullptr || out == nullptr || outChars == 0)
        {
            return false;
        }
        out[0] = '\0';
        int written = WideCharToMultiByte(CP_UTF8, 0, input, -1, out, static_cast<int>(outChars), nullptr, nullptr);
        if (written <= 0)
        {
            return false;
        }
        out[outChars - 1] = '\0';
        return true;
    }

    const wchar_t *ComponentDisplayName(UINT32 component) noexcept
    {
        switch (component)
        {
        case SKUGGA_IPC_HOOK_POLICY_COMPONENT_NT:
            return L"nt";
        case SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE:
            return L"module";
        case SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK:
            return L"winsock";
        default:
            return L"hook";
        }
    }

} // namespace skugga::injector
