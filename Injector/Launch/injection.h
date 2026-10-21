#pragma once

#include "Core/runner_core.h"

namespace skugga::injector
{
    std::wstring WideBaseName(const std::wstring &path);
    bool GetRemoteModuleBase(DWORD pid, const std::wstring &baseName, UINT64 &base);
    bool QueryPortableExecutableMachine(const std::wstring &path, WORD &machine) noexcept;
    bool RelaunchForTargetArchitecture(int argc, wchar_t **argv, const std::wstring &targetPath, int &exitCode);
    bool InjectDllIntoChild(ServerContext &ctx, HANDLE process, const std::wstring &dllPath);
} // namespace skugga::injector
