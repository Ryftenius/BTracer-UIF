#include "../ABI/packet_validation.h"
#include <cstdio>
#include <cstdint>
#include <cstring>

int main()
{
    unsigned checks = 0;
    const auto check = [&checks](bool condition)
    {
        ++checks;
        return condition;
    };
    SKUGGA_IPC_HOOK_EVENT event{};
    event.Kind = SkuggaIpcHookEventNt;
    if (!check(SkuggaValidEvent(event)))
        return 1;
    event.ArgCount = SKUGGA_IPC_MAX_HOOK_ARGS;
    event.StackCount = SKUGGA_IPC_MAX_HOOK_STACK_FRAMES;
    event.DataSize = SKUGGA_IPC_MAX_HOOK_DATA_SAMPLE;
    if (!check(SkuggaValidEvent(event)))
        return 2;
    ++event.ArgCount;
    if (!check(!SkuggaValidEvent(event)))
        return 3;
    --event.ArgCount;
    ++event.StackCount;
    if (!check(!SkuggaValidEvent(event)))
        return 4;
    --event.StackCount;
    ++event.DataSize;
    if (!check(!SkuggaValidEvent(event)))
        return 5;
    --event.DataSize;
    std::memset(event.ApiName, 'A', sizeof(event.ApiName));
    if (!check(!SkuggaValidEvent(event)))
        return 6;
    event.ApiName[sizeof(event.ApiName) - 1] = '\0';
    if (!check(SkuggaValidEvent(event)))
        return 7;
    std::memset(event.ModuleName, 'A', sizeof(event.ModuleName));
    if (!check(!SkuggaValidEvent(event)))
        return 8;
    event.ModuleName[sizeof(event.ModuleName) - 1] = '\0';
    event.Kind = SkuggaIpcHookEventModule + 1;
    if (!check(!SkuggaValidEvent(event)))
        return 9;
    SKUGGA_IPC_PACKET packet{};
    packet.Command = SkuggaIpcCommandPublishHookEventBatch;
    packet.Payload.HookEventBatch.Count = SKUGGA_IPC_MAX_HOOK_EVENT_BATCH;
    if (!check(SkuggaValidEventPacket(packet)))
        return 10;
    packet.Payload.HookEventBatch.Events[SKUGGA_IPC_MAX_HOOK_EVENT_BATCH - 1].StackCount = UINT32_MAX;
    if (!check(!SkuggaValidEventPacket(packet)))
        return 11;
    packet.Payload.HookEventBatch.Count = UINT32_MAX;
    if (!check(!SkuggaValidEventPacket(packet)))
        return 12;
    packet.Command = SkuggaIpcCommandPublishHookEvent;
    packet.Payload.HookEvent = event;
    if (!check(!SkuggaValidEventPacket(packet)))
        return 13;
    std::printf("Packet validation: %u checks passed\n", checks);
    return 0;
}
