#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <string>

namespace skugga::injector
{
    struct ServerContext;
}

namespace skugga::mapper
{
    bool PauseDebuggedChildAtEntrypoint(skugga::injector::ServerContext &ctx, PROCESS_INFORMATION &pi);
    bool MapDllIntoChild(skugga::injector::ServerContext &ctx, HANDLE process, const std::wstring &dllPath);
} // namespace skugga::mapper
