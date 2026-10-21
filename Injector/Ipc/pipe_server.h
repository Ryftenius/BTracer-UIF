#pragma once

#include "Core/runner_core.h"

namespace skugga::injector
{
    void PrintHookEvent(const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    void HandleHookEvent(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    bool HandlePacket(ServerContext &ctx, HANDLE pipe, const SKUGGA_IPC_PACKET &request);
    DWORD WINAPI PipeServerThread(LPVOID parameter);
} // namespace skugga::injector
