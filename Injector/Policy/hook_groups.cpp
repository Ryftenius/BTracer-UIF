#include "Core/runner_help.h"
#include "Policy/hook_catalog.h"

namespace skugga::injector
{
    struct HookNameEntry
    {
        const wchar_t *Name;
        UINT32 Component;
    };

    static constexpr HookNameEntry kKnownModuleHooks[] = {
        {L"LoadLibraryA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LoadLibraryW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LoadLibraryExA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LoadLibraryExW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LdrLoadDll", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"RtlAddFunctionTable", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"RtlInstallFunctionTableCallback", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"RtlDeleteFunctionTable", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"RtlAddVectoredExceptionHandler", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"RtlRemoveVectoredExceptionHandler", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"SetUnhandledExceptionFilter", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EventRegister", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EventUnregister", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"StartTraceW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EnableTraceEx2", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EtwEventWrite", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EtwEventWriteEx", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EtwEventWriteFull", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EtwEventWriteTransfer", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiInitialize", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiUninitialize", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiOpenSession", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiCloseSession", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiScanBuffer", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiScanString", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AmsiNotifyOperation", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"WinHttpSendRequest", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"HttpSendRequestW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"HttpSendRequestA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"WinHttpConnect", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"WinHttpOpenRequest", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"InternetConnectW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"InternetConnectA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"HttpOpenRequestW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"HttpOpenRequestA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"EncryptMessage", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"DecryptMessage", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CryptUnprotectData", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"NCryptUnprotectSecret", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"NCryptOpenStorageProvider", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"NCryptOpenKey", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"NCryptDecrypt", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CredReadA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CredReadW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CredEnumerateA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CredEnumerateW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CredReadDomainCredentialsA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CredReadDomainCredentialsW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LsaConnectUntrusted", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LsaLookupAuthenticationPackage", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LsaCallAuthenticationPackage", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LsaOpenPolicy", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"LsaQueryInformationPolicy", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AcquireCredentialsHandleA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AcquireCredentialsHandleW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"InitializeSecurityContextA", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"InitializeSecurityContextW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AcceptSecurityContext", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"VaultEnumerateVaults", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"VaultOpenVault", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"VaultEnumerateItems", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"VaultGetItem", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CreateJobObjectW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"OpenJobObjectW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"AssignProcessToJobObject", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"SetInformationJobObject", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CfAbortOperation", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CfRegisterSyncRoot", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CfConnectSyncRoot", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CfCreatePlaceholders", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CoCreateInstance", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CoInitializeEx", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
        {L"CoInitializeSecurity", SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE},
    };

    static constexpr HookNameEntry kKnownWinsockHooks[] = {
        {L"WSASend", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"WSARecv", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"send", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"recv", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"connect", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"WSAConnect", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"GetAddrInfoW", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"getaddrinfo", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"DnsQuery_W", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
        {L"DnsQuery_A", SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK},
    };
    bool KnownHookComponent(const wchar_t *name, UINT32 &component) noexcept
    {
        if (name == nullptr || name[0] == L'\0')
        {
            return false;
        }
        if (_wcsnicmp(name, L"Nt", 2) == 0)
        {
            component = SKUGGA_IPC_HOOK_POLICY_COMPONENT_NT;
            return true;
        }
        for (const auto &entry : kKnownModuleHooks)
        {
            if (_wcsicmp(entry.Name, name) == 0)
            {
                component = entry.Component;
                return true;
            }
        }
        for (const auto &entry : kKnownWinsockHooks)
        {
            if (_wcsicmp(entry.Name, name) == 0)
            {
                component = entry.Component;
                return true;
            }
        }
        return false;
    }

    bool IsKnownHookGroupName(const wchar_t *groupName)
    {
        std::wstring group = ToLowerWide(groupName);
        static constexpr const wchar_t *kGroups[] = {
            L"behavior",   L"behaviour", L"smart",   L"memory",      L"mem",        L"protect",       L"protection",
            L"thread",     L"threads",   L"process", L"proc",        L"file",       L"files",         L"token",
            L"tokens",     L"remote",    L"remotes", L"injection",   L"inject",     L"anti-analysis", L"antianalysis",
            L"anti-debug", L"antidebug", L"loader",  L"load",        L"loads",      L"amsi",          L"etw",
            L"eventing",   L"winsock",   L"ws",      L"dns",         L"http",       L"web",           L"network",
            L"net",        L"crypto",    L"secrets", L"credentials", L"credential", L"creds",         L"sspi",
            L"auth",       L"vault",     L"vaults",  L"dpapi",       L"ncrypt",     L"com",           L"ole",
            L"jobs",       L"job",       L"cloud",   L"cloudfiles",  L"exceptions", L"exception",     L"veh",
            L"unwind",
        };
        for (const wchar_t *known : kGroups)
        {
            if (group == known)
            {
                return true;
            }
        }
        return false;
    }
    bool AddHookGroup(RunnerOptions &options, const wchar_t *groupName, bool log)
    {
        std::wstring group = ToLowerWide(groupName);
        UINT32 start = options.CliPolicy.RuleCount;

        auto add = [&](UINT32 component, const wchar_t *name) -> bool
        { return AddRuleIfMissing(options, component, name, log); };
        auto addNt = [&](const wchar_t *name) -> bool { return add(SKUGGA_IPC_HOOK_POLICY_COMPONENT_NT, name); };
        auto addModule = [&](const wchar_t *name) -> bool
        { return add(SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE, name); };
        auto addNtMany = [&](const wchar_t *const *names, std::size_t count) -> bool
        {
            bool localOk = true;
            for (std::size_t i = 0; i < count; ++i)
            {
                localOk = addNt(names[i]) && localOk;
            }
            return localOk;
        };
        auto addModuleMany = [&](const wchar_t *const *names, std::size_t count) -> bool
        {
            bool localOk = true;
            for (std::size_t i = 0; i < count; ++i)
            {
                localOk = addModule(names[i]) && localOk;
            }
            return localOk;
        };

        bool ok = true;
        if (group == L"behavior" || group == L"behaviour" || group == L"smart")
        {
            static constexpr const wchar_t *kBehavior[] = {
                L"NtAllocateVirtualMemory", L"NtAllocateVirtualMemoryEx",
                L"NtProtectVirtualMemory",  L"NtWriteVirtualMemory",
                L"NtReadVirtualMemory",     L"NtQueryVirtualMemory",
                L"NtCreateThreadEx",        L"NtCreateThread",
                L"NtQueueApcThread",        L"NtQueueApcThreadEx",
                L"NtQueueApcThreadEx2",     L"NtMapViewOfSection",
                L"NtMapViewOfSectionEx",    L"NtCreateSection",
            };
            ok = addNtMany(kBehavior, RTL_NUMBER_OF(kBehavior));
        }
        else if (group == L"memory" || group == L"mem" || group == L"protect" || group == L"protection")
        {
            static constexpr const wchar_t *kMemory[] = {
                L"NtAllocateVirtualMemory", L"NtAllocateVirtualMemoryEx", L"NtProtectVirtualMemory",
                L"NtWriteVirtualMemory",    L"NtReadVirtualMemory",       L"NtQueryVirtualMemory",
                L"NtCreateSection",         L"NtMapViewOfSection",        L"NtMapViewOfSectionEx",
                L"NtUnmapViewOfSection",    L"NtUnmapViewOfSectionEx",
            };
            ok = addNtMany(kMemory, RTL_NUMBER_OF(kMemory));
        }
        else if (group == L"thread" || group == L"threads")
        {
            static constexpr const wchar_t *kThreads[] = {
                L"NtCreateThread",           L"NtCreateThreadEx",   L"NtOpenThread",       L"NtGetNextThread",
                L"NtQueryInformationThread", L"NtSetContextThread", L"NtGetContextThread", L"NtSuspendThread",
                L"NtResumeThread",           L"NtQueueApcThread",   L"NtQueueApcThreadEx", L"NtQueueApcThreadEx2",
            };
            ok = addNtMany(kThreads, RTL_NUMBER_OF(kThreads));
        }
        else if (group == L"process" || group == L"proc")
        {
            static constexpr const wchar_t *kProcess[] = {
                L"NtOpenProcess",     L"NtQueryInformationProcess", L"NtTerminateProcess",
                L"NtDuplicateObject", L"NtQuerySystemInformation",  L"NtQuerySystemInformationEx",
            };
            ok = addNtMany(kProcess, RTL_NUMBER_OF(kProcess));
        }
        else if (group == L"file" || group == L"files")
        {
            static constexpr const wchar_t *kFiles[] = {
                L"NtOpenFile",           L"NtCreateSection",      L"NtQuerySection",         L"NtMapViewOfSection",
                L"NtMapViewOfSectionEx", L"NtUnmapViewOfSection", L"NtUnmapViewOfSectionEx",
            };
            ok = addNtMany(kFiles, RTL_NUMBER_OF(kFiles));
        }
        else if (group == L"token" || group == L"tokens")
        {
            static constexpr const wchar_t *kTokens[] = {
                L"NtOpenProcessToken",
                L"NtOpenThreadToken",
                L"NtOpenProcessTokenEx",
                L"NtOpenThreadTokenEx",
            };
            ok = addNtMany(kTokens, RTL_NUMBER_OF(kTokens));
        }
        else if (group == L"remote" || group == L"remotes" || group == L"injection" || group == L"inject")
        {
            static constexpr const wchar_t *kRemote[] = {
                L"NtOpenProcess",           L"NtOpenThread",
                L"NtDuplicateObject",       L"NtReadVirtualMemory",
                L"NtWriteVirtualMemory",    L"NtQueryVirtualMemory",
                L"NtAllocateVirtualMemory", L"NtAllocateVirtualMemoryEx",
                L"NtProtectVirtualMemory",  L"NtCreateThread",
                L"NtCreateThreadEx",        L"NtSetContextThread",
                L"NtGetContextThread",      L"NtSuspendThread",
                L"NtResumeThread",          L"NtQueueApcThread",
                L"NtQueueApcThreadEx",      L"NtQueueApcThreadEx2",
            };
            ok = addNtMany(kRemote, RTL_NUMBER_OF(kRemote));
        }
        else if (group == L"anti-analysis" || group == L"antianalysis" || group == L"anti-debug" ||
                 group == L"antidebug")
        {
            static constexpr const wchar_t *kAntiNt[] = {
                L"NtQueryInformationProcess",  L"NtQueryInformationThread", L"NtQuerySystemInformation",
                L"NtQuerySystemInformationEx", L"NtQueryBootOptions",
            };
            static constexpr const wchar_t *kAntiModule[] = {
                L"RtlAddVectoredExceptionHandler",  L"RtlRemoveVectoredExceptionHandler",
                L"SetUnhandledExceptionFilter",     L"RtlAddFunctionTable",
                L"RtlInstallFunctionTableCallback", L"RtlDeleteFunctionTable",
            };
            ok = addNtMany(kAntiNt, RTL_NUMBER_OF(kAntiNt)) && addModuleMany(kAntiModule, RTL_NUMBER_OF(kAntiModule));
        }
        else if (group == L"loader" || group == L"load" || group == L"loads")
        {
            static constexpr const wchar_t *kLoader[] = {
                L"LdrLoadDll", L"LoadLibraryA", L"LoadLibraryW", L"LoadLibraryExA", L"LoadLibraryExW",
            };
            ok = addModuleMany(kLoader, RTL_NUMBER_OF(kLoader));
        }
        else if (group == L"amsi")
        {
            static constexpr const wchar_t *kAmsi[] = {
                L"AmsiInitialize", L"AmsiUninitialize", L"AmsiOpenSession",     L"AmsiCloseSession",
                L"AmsiScanBuffer", L"AmsiScanString",   L"AmsiNotifyOperation",
            };
            ok = addModuleMany(kAmsi, RTL_NUMBER_OF(kAmsi));
        }
        else if (group == L"etw" || group == L"eventing")
        {
            static constexpr const wchar_t *kEtw[] = {
                L"EventRegister", L"EventUnregister", L"StartTraceW",       L"EnableTraceEx2",
                L"EtwEventWrite", L"EtwEventWriteEx", L"EtwEventWriteFull", L"EtwEventWriteTransfer",
            };
            ok = addModuleMany(kEtw, RTL_NUMBER_OF(kEtw));
        }
        else if (group == L"winsock" || group == L"ws" || group == L"dns")
        {
            for (const auto &entry : kKnownWinsockHooks)
            {
                ok = add(entry.Component, entry.Name) && ok;
            }
        }
        else if (group == L"http" || group == L"web")
        {
            static constexpr const wchar_t *kHttp[] = {
                L"WinHttpConnect",   L"WinHttpOpenRequest", L"WinHttpSendRequest",
                L"InternetConnectW", L"InternetConnectA",   L"HttpOpenRequestW",
                L"HttpOpenRequestA", L"HttpSendRequestW",   L"HttpSendRequestA",
            };
            ok = addModuleMany(kHttp, RTL_NUMBER_OF(kHttp));
        }
        else if (group == L"network" || group == L"net")
        {
            ok = AddHookGroup(options, L"winsock", log) && AddHookGroup(options, L"http", log) &&
                 addModule(L"EncryptMessage") && addModule(L"DecryptMessage");
        }
        else if (group == L"crypto" || group == L"secrets")
        {
            static constexpr const wchar_t *kCrypto[] = {
                L"CryptUnprotectData", L"NCryptUnprotectSecret", L"NCryptOpenStorageProvider",
                L"NCryptOpenKey",      L"NCryptDecrypt",         L"EncryptMessage",
                L"DecryptMessage",
            };
            ok = addModuleMany(kCrypto, RTL_NUMBER_OF(kCrypto));
        }
        else if (group == L"credentials" || group == L"credential" || group == L"creds")
        {
            static constexpr const wchar_t *kCreds[] = {
                L"CredReadA",
                L"CredReadW",
                L"CredEnumerateA",
                L"CredEnumerateW",
                L"CredReadDomainCredentialsA",
                L"CredReadDomainCredentialsW",
                L"LsaConnectUntrusted",
                L"LsaLookupAuthenticationPackage",
                L"LsaCallAuthenticationPackage",
                L"LsaOpenPolicy",
                L"LsaQueryInformationPolicy",
                L"VaultEnumerateVaults",
                L"VaultOpenVault",
                L"VaultEnumerateItems",
                L"VaultGetItem",
                L"CryptUnprotectData",
                L"NCryptUnprotectSecret",
            };
            ok = addModuleMany(kCreds, RTL_NUMBER_OF(kCreds));
        }
        else if (group == L"sspi" || group == L"auth")
        {
            static constexpr const wchar_t *kSspi[] = {
                L"LsaConnectUntrusted",
                L"LsaLookupAuthenticationPackage",
                L"LsaCallAuthenticationPackage",
                L"AcquireCredentialsHandleA",
                L"AcquireCredentialsHandleW",
                L"InitializeSecurityContextA",
                L"InitializeSecurityContextW",
                L"AcceptSecurityContext",
                L"EncryptMessage",
                L"DecryptMessage",
            };
            ok = addModuleMany(kSspi, RTL_NUMBER_OF(kSspi));
        }
        else if (group == L"vault" || group == L"vaults")
        {
            static constexpr const wchar_t *kVault[] = {
                L"VaultEnumerateVaults",
                L"VaultOpenVault",
                L"VaultEnumerateItems",
                L"VaultGetItem",
            };
            ok = addModuleMany(kVault, RTL_NUMBER_OF(kVault));
        }
        else if (group == L"dpapi" || group == L"ncrypt")
        {
            static constexpr const wchar_t *kDpapi[] = {
                L"CryptUnprotectData", L"NCryptUnprotectSecret", L"NCryptOpenStorageProvider",
                L"NCryptOpenKey",      L"NCryptDecrypt",
            };
            ok = addModuleMany(kDpapi, RTL_NUMBER_OF(kDpapi));
        }
        else if (group == L"com" || group == L"ole")
        {
            static constexpr const wchar_t *kCom[] = {
                L"CoInitializeEx",
                L"CoInitializeSecurity",
                L"CoCreateInstance",
            };
            ok = addModuleMany(kCom, RTL_NUMBER_OF(kCom));
        }
        else if (group == L"jobs" || group == L"job")
        {
            static constexpr const wchar_t *kJobs[] = {
                L"CreateJobObjectW",
                L"OpenJobObjectW",
                L"AssignProcessToJobObject",
                L"SetInformationJobObject",
            };
            ok = addModuleMany(kJobs, RTL_NUMBER_OF(kJobs));
        }
        else if (group == L"cloud" || group == L"cloudfiles")
        {
            static constexpr const wchar_t *kCloud[] = {
                L"CfAbortOperation",
                L"CfRegisterSyncRoot",
                L"CfConnectSyncRoot",
                L"CfCreatePlaceholders",
            };
            ok = addModuleMany(kCloud, RTL_NUMBER_OF(kCloud));
        }
        else if (group == L"exceptions" || group == L"exception" || group == L"veh" || group == L"unwind")
        {
            static constexpr const wchar_t *kExceptions[] = {
                L"RtlAddVectoredExceptionHandler",  L"RtlRemoveVectoredExceptionHandler",
                L"SetUnhandledExceptionFilter",     L"RtlAddFunctionTable",
                L"RtlInstallFunctionTableCallback", L"RtlDeleteFunctionTable",
            };
            ok = addModuleMany(kExceptions, RTL_NUMBER_OF(kExceptions));
        }
        else
        {
            std::wprintf(L"[skugga] unknown hook group: %ls\n", groupName != nullptr ? groupName : L"<null>");
            return false;
        }

        if (!ok)
        {
            return false;
        }
        MarkRecentRules(options, start, options.CliPolicy.RuleCount - start);
        return true;
    }

} // namespace skugga::injector
