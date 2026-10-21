#include "Telemetry/cli_events.h"

namespace skugga::injector
{
    const SKUGGA_IPC_HOOK_POLICY_RULE *FindCliRule(const ServerContext &ctx,
                                                   const SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept
    {
        UINT32 component = 0;
        switch (eventRecord.Kind)
        {
        case SkuggaIpcHookEventNt:
            component = SKUGGA_IPC_HOOK_POLICY_COMPONENT_NT;
            break;
        case SkuggaIpcHookEventModule:
            component = SKUGGA_IPC_HOOK_POLICY_COMPONENT_MODULE;
            break;
        case SkuggaIpcHookEventWinsock:
            component = SKUGGA_IPC_HOOK_POLICY_COMPONENT_WINSOCK;
            break;
        default:
            return nullptr;
        }

        UINT32 count = ctx.CliPolicy.RuleCount < SKUGGA_IPC_MAX_HOOK_POLICY_RULES ? ctx.CliPolicy.RuleCount
                                                                                  : SKUGGA_IPC_MAX_HOOK_POLICY_RULES;
        for (UINT32 i = 0; i < count; ++i)
        {
            const auto &rule = ctx.CliPolicy.Rules[i];
            if (rule.Component == component && _stricmp(rule.ApiName, eventRecord.ApiName) == 0)
            {
                return &rule;
            }
        }
        return nullptr;
    }
    DWORD CliReadyMaskForPolicy(const ServerContext &ctx) noexcept
    {
        if (!ctx.CliMode)
        {
            return SKUGGA_SDK_READY_CORE_MASK;
        }
        DWORD mask = SKUGGA_IPC_HOOK_READY_FLAG_IPC_CONNECTED;
        const DWORD flags = ctx.CliPolicy.Flags;
        if ((flags & SKUGGA_IPC_HOOK_POLICY_FLAG_EXPLICIT_NT) != 0)
        {
            mask |= SKUGGA_IPC_HOOK_READY_FLAG_NT;
        }
        if ((flags & (SKUGGA_IPC_HOOK_POLICY_FLAG_EXPLICIT_MODULE | SKUGGA_IPC_HOOK_POLICY_FLAG_EXPLICIT_WINSOCK)) != 0)
        {
            mask |= SKUGGA_IPC_HOOK_READY_FLAG_MODULE;
        }
        return mask;
    }

    bool RuleApiIs(const SKUGGA_IPC_HOOK_POLICY_RULE &rule, const char *apiName) noexcept
    {
        return rule.Component == SKUGGA_IPC_HOOK_POLICY_COMPONENT_NT && rule.ApiName[0] != '\0' &&
               _stricmp(rule.ApiName, apiName) == 0;
    }
} // namespace skugga::injector
