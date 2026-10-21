#pragma once
#include "skugga_ipc.h"
#include <cstring>

inline bool SkuggaValidEvent(const SKUGGA_IPC_HOOK_EVENT &event) noexcept
{
    return event.Kind <= SkuggaIpcHookEventModule && event.ArgCount <= SKUGGA_IPC_MAX_HOOK_ARGS &&
           event.StackCount <= SKUGGA_IPC_MAX_HOOK_STACK_FRAMES && event.DataSize <= SKUGGA_IPC_MAX_HOOK_DATA_SAMPLE &&
           std::memchr(event.ApiName, '\0', sizeof(event.ApiName)) != nullptr &&
           std::memchr(event.ModuleName, '\0', sizeof(event.ModuleName)) != nullptr;
}

// Validate a whole batch before its first event can affect host state.
inline bool SkuggaValidEventPacket(const SKUGGA_IPC_PACKET &packet) noexcept
{
    if (packet.Command == SkuggaIpcCommandPublishHookEvent)
        return SkuggaValidEvent(packet.Payload.HookEvent);
    if (packet.Command == SkuggaIpcCommandPublishHookEventBatch)
    {
        const auto &batch = packet.Payload.HookEventBatch;
        if (batch.Count > SKUGGA_IPC_MAX_HOOK_EVENT_BATCH)
            return false;
        for (UINT32 i = 0; i < batch.Count; ++i)
            if (!SkuggaValidEvent(batch.Events[i]))
                return false;
    }
    return true;
}
