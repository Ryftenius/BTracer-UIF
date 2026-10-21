#include "Ipc/pipe_server.h"
#include "ABI/packet_validation.h"
#include "Core/runner_console.h"
#include "Diagnostics/diagnostics.h"
#include "Telemetry/cli_events.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/smart_capture.h"
#include "Telemetry/smart_summary.h"
#include "Telemetry/process_symbols.h"

namespace skugga::injector
{
    void PrintHookEvent(const SKUGGA_IPC_HOOK_EVENT &eventRecord)
    {
        char sampleSuffix[224]{};
        FormatEventSampleSuffix(eventRecord, sampleSuffix, RTL_NUMBER_OF(sampleSuffix));

        ColorPrintf(LogColor::Info,
                    "[skugga] event pid=%lu tid=%lu kind=%s op=%lu api=%s module=%s "
                    "caller=0x%llX "
                    "c0=0x%llX c1=0x%llX c2=0x%llX c3=0x%llX%s\n",
                    static_cast<unsigned long>(eventRecord.ProcessId), static_cast<unsigned long>(eventRecord.ThreadId),
                    KindName(eventRecord.Kind), static_cast<unsigned long>(eventRecord.Operation),
                    eventRecord.ApiName[0] != '\0' ? eventRecord.ApiName : "<none>",
                    eventRecord.ModuleName[0] != '\0' ? eventRecord.ModuleName : "<none>",
                    static_cast<unsigned long long>(eventRecord.Caller),
                    static_cast<unsigned long long>(eventRecord.Context0),
                    static_cast<unsigned long long>(eventRecord.Context1),
                    static_cast<unsigned long long>(eventRecord.Context2),
                    static_cast<unsigned long long>(eventRecord.Context3), sampleSuffix);
    }

    void HandleHookEvent(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &originalEvent)
    {
        SKUGGA_IPC_HOOK_EVENT eventRecord = originalEvent;
        if (!ctx.IncludeInternals)
        {
            UINT32 kept = 0;
            const UINT32 count = std::min<UINT32>(eventRecord.StackCount, SKUGGA_IPC_MAX_HOOK_STACK_FRAMES);
            for (UINT32 i = 0; i < count; ++i)
            {
                const auto *module = FindChildModule(ctx, eventRecord.Stack[i]);
                if (module != nullptr && _stricmp(module->Name, "SKUGGA.dll") == 0)
                    continue;
                eventRecord.Stack[kept++] = eventRecord.Stack[i];
            }
            for (UINT32 i = kept; i < count; ++i)
                eventRecord.Stack[i] = 0;
            eventRecord.StackCount = kept;
        }
        ctx.HookEventCount.fetch_add(1, std::memory_order_relaxed);
        if (eventRecord.Kind == SkuggaIpcHookEventIntegrity &&
            (eventRecord.Operation == IX_HOOK_EVENT_OP_LAUNCH_GATE_ENTRY ||
             eventRecord.Operation == IX_HOOK_EVENT_OP_LAUNCH_GATE_TLS_CALLBACK))
        {
            ctx.LaunchGateTrapCount.fetch_add(1, std::memory_order_relaxed);
            ColorPrintf(LogColor::Lifecycle, "[skugga] launch-gate trap op=%lu tid=%lu caller=0x%llX page=0x%llX\n",
                        static_cast<unsigned long>(eventRecord.Operation),
                        static_cast<unsigned long>(eventRecord.ThreadId),
                        static_cast<unsigned long long>(eventRecord.Context0),
                        static_cast<unsigned long long>(eventRecord.Context1));
        }
        if (eventRecord.Kind < RTL_NUMBER_OF(ctx.EventKindCounts))
        {
            ctx.EventKindCounts[eventRecord.Kind] += 1;
        }
        WriteRawEvent(ctx, originalEvent);
        CaptureSelfMapEvent(ctx, eventRecord);
        InvalidateVadCacheForEvent(ctx, eventRecord);
        CaptureSmartEvent(ctx, eventRecord);
        MaybePrintSmartSummary(ctx);

        if (ctx.CliMode)
        {
            if (!ctx.IncludeInternals && eventRecord.Kind == SkuggaIpcHookEventIntegrity &&
                eventRecord.Operation == IX_HOOK_EVENT_OP_IX_SELF_MAP_ENTRY)
            {
                ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (!ShouldSuppressRawForSmart(ctx, eventRecord) && ShouldPrintCliEvent(ctx, eventRecord))
            {
                SKUGGA_IPC_HOOK_EVENT printableEvent = eventRecord;
                if (ApplyCliRepeatAnnotation(ctx, printableEvent))
                {
                    ctx.PrintedEventCount.fetch_add(1, std::memory_order_relaxed);
                    PrintCliGenericEvent(ctx, printableEvent);
                }
                else
                {
                    ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
            return;
        }

        DWORD printed = ctx.PrintedEventCount.load(std::memory_order_relaxed);
        bool shouldPrint =
            ctx.Verbose || printed < 24 || (eventRecord.Kind == SkuggaIpcHookEventWinsock && printed < 64);
        if (shouldPrint)
        {
            ctx.PrintedEventCount.fetch_add(1, std::memory_order_relaxed);
            PrintHookEvent(eventRecord);
            return;
        }

        DWORD suppressed = ctx.SuppressedEventCount.fetch_add(1, std::memory_order_relaxed);
        if (suppressed == 0)
        {
            std::printf("[skugga] suppressing additional event details; rerun with "
                        "--verbose for full dump\n");
        }
    }

    bool HandlePacket(ServerContext &ctx, HANDLE pipe, const SKUGGA_IPC_PACKET &request)
    {
        SKUGGA_IPC_PACKET response{};
        response.Magic = SKUGGA_IPC_MAGIC;
        response.Version = SKUGGA_IPC_VERSION;
        response.PacketType = SkuggaIpcPacketResponse;
        response.Command = request.Command;
        response.Sequence = request.Sequence;
        response.Status = ERROR_SUCCESS;

        if (request.Magic != SKUGGA_IPC_MAGIC || request.Version != SKUGGA_IPC_VERSION ||
            request.PacketType != SkuggaIpcPacketRequest || !SkuggaValidEventPacket(request))
        {
            response.Status = ERROR_INVALID_DATA;
            return WritePacket(pipe, response);
        }

        switch (request.Command)
        {
        case SkuggaIpcCommandHandshake:
            response.Payload.HandshakeResponse.NegotiatedVersion = SKUGGA_IPC_VERSION;
            response.Payload.HandshakeResponse.Capabilities = 1;
            break;
        case SkuggaIpcCommandNotifyHookReady:
        {
            DWORD localMask = request.Payload.NotifyHookReadyRequest.ReadyMask;
            DWORD observed = ctx.ReadyMask.fetch_or(localMask, std::memory_order_acq_rel) | localMask;
            const DWORD requiredMask = CliReadyMaskForPolicy(ctx);
            response.Payload.NotifyHookReadyResponse.ProcessId = request.Payload.NotifyHookReadyRequest.ProcessId;
            response.Payload.NotifyHookReadyResponse.ObservedMask = observed;
            response.Payload.NotifyHookReadyResponse.RequiredMask = requiredMask;
            response.Payload.NotifyHookReadyResponse.PendingCommand = 0;
            char components[64]{};
            FormatReadyComponents(observed, components, RTL_NUMBER_OF(components));
            TaggedPrintf(LogColor::Info, "[skugga:ready]",
                         " pid=%lu update=0x%08lX active=0x%08lX "
                         "components=%s\n",
                         static_cast<unsigned long>(request.Payload.NotifyHookReadyRequest.ProcessId),
                         static_cast<unsigned long>(localMask), static_cast<unsigned long>(observed), components);
            if ((observed & requiredMask) == requiredMask)
            {
                SetEvent(ctx.ReadyEvent);
            }
            break;
        }
        case SkuggaIpcCommandQueryHookPolicy:
            response.Payload.QueryHookPolicyResponse = ctx.CliPolicy;
            response.Payload.QueryHookPolicyResponse.PolicyVersion = SKUGGA_IPC_HOOK_POLICY_VERSION;
            break;
        case SkuggaIpcCommandPublishHookEvent:
            HandleHookEvent(ctx, request.Payload.HookEvent);
            break;
        case SkuggaIpcCommandPublishHookEventBatch:
        {
            UINT32 count = request.Payload.HookEventBatch.Count;
            if (count > SKUGGA_IPC_MAX_HOOK_EVENT_BATCH)
            {
                response.Status = ERROR_INVALID_DATA;
                break;
            }
            for (UINT32 i = 0; i < count; ++i)
            {
                HandleHookEvent(ctx, request.Payload.HookEventBatch.Events[i]);
            }
            break;
        }
        case SkuggaIpcCommandRegisterInstrumentationRange:
        case SkuggaIpcCommandRegisterHookPatch:
        case SkuggaIpcCommandRegisterProcessInstrumentationCallback:
            break;
        default:
            response.Status = ERROR_INVALID_FUNCTION;
            break;
        }

        return WritePacket(pipe, response);
    }

    DWORD WINAPI PipeServerThread(LPVOID parameter)
    {
        auto *ctx = static_cast<ServerContext *>(parameter);
        HANDLE pipe =
            CreateNamedPipeW(ctx->PipeName.c_str(), PIPE_ACCESS_DUPLEX,
                             PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                             kPipeBufferBytes, kPipeBufferBytes, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            std::printf("[skugga] CreateNamedPipe failed gle=%lu\n", GetLastError());
            SetEvent(ctx->ReadyEvent);
            return 1;
        }

        std::printf("[skugga:startup] pipe=%ls state=listening\n", ctx->PipeName.c_str());
        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            std::printf("[skugga] ConnectNamedPipe failed gle=%lu\n", GetLastError());
            CloseHandle(pipe);
            SetEvent(ctx->ReadyEvent);
            return 1;
        }

        std::printf("[skugga:startup] telemetry_client=connected\n");
        while (!ctx->Stop.load(std::memory_order_acquire))
        {
            SKUGGA_IPC_PACKET request{};
            DWORD read = 0;
            if (!ReadFile(pipe, &request, sizeof(request), &read, nullptr))
            {
                DWORD err = GetLastError();
                if (err != ERROR_BROKEN_PIPE && err != ERROR_PIPE_NOT_CONNECTED)
                {
                    std::printf("[skugga] pipe read failed gle=%lu\n", err);
                }
                break;
            }
            if (read != sizeof(request))
            {
                std::printf("[skugga] short packet read bytes=%lu expected=%zu\n", read, sizeof(request));
                break;
            }
            if (!HandlePacket(*ctx, pipe, request))
            {
                DWORD err = GetLastError();
                if (err != ERROR_BROKEN_PIPE && err != ERROR_NO_DATA && err != ERROR_PIPE_NOT_CONNECTED)
                {
                    std::printf("[skugga] response write failed gle=%lu\n", err);
                }
                break;
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 0;
    }
} // namespace skugga::injector
