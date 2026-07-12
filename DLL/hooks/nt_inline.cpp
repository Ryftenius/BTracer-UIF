#include "nt_methods.h"

#include <Windows.h>
#include <cstring>

namespace IX_NT_METHODS
{
    static bool InstallInlinePatch(void *target, void *hook, std::uint8_t original[16]) noexcept
    {
        auto *dst = static_cast<std::uint8_t *>(target);
        const std::size_t patchSize = NtHookPatchSize(IXIPC_HOOK_METHOD_INLINE);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }

        std::memcpy(original, dst, patchSize);
#if defined(_WIN64)
        dst[0] = 0x48;
        dst[1] = 0xB8;
        *reinterpret_cast<void **>(&dst[2]) = hook;
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        std::memset(dst + 12, 0xCC, 4);
#else
        dst[0] = 0xB8;
        *reinterpret_cast<void **>(&dst[1]) = hook;
        dst[5] = 0xFF;
        dst[6] = 0xE0;
#endif

        DWORD temp = 0;
        (void)VirtualProtect(dst, patchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, patchSize);
        return true;
    }

    static void RemoveInlinePatch(void *target, const std::uint8_t original[16]) noexcept
    {
        auto *dst = static_cast<std::uint8_t *>(target);
        const std::size_t patchSize = NtHookPatchSize(IXIPC_HOOK_METHOD_INLINE);

        DWORD oldProtect = 0;
        if (!VirtualProtect(dst, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return;
        }

        std::memcpy(dst, original, patchSize);

        DWORD temp = 0;
        (void)VirtualProtect(dst, patchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), dst, patchSize);
    }

    static bool CheckInlinePatch(void *target, void *hook) noexcept
    {
        if (target == nullptr || hook == nullptr)
        {
            return false;
        }

        const auto *bytes = static_cast<const std::uint8_t *>(target);
        void *patchedTarget = nullptr;
        __try
        {
#if defined(_WIN64)
            std::memcpy(&patchedTarget, &bytes[2], sizeof(patchedTarget));
            return bytes[0] == 0x48 && bytes[1] == 0xB8 && patchedTarget == hook && bytes[10] == 0xFF &&
                   bytes[11] == 0xE0;
#else
            std::memcpy(&patchedTarget, &bytes[1], sizeof(patchedTarget));
            return bytes[0] == 0xB8 && patchedTarget == hook && bytes[5] == 0xFF && bytes[6] == 0xE0;
#endif
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool InstallNtHookPatch(NtHookPatch &patch) noexcept;
    void RemoveNtHookPatch(const NtHookPatch &patch) noexcept;
    bool CheckNtHookPatch(const NtHookPatch &patch) noexcept;

    bool InstallNtInlineHook(NtHookPatch &patch) noexcept
    {
        if (patch.Target == nullptr || patch.HookEntry == nullptr || patch.OriginalBytes == nullptr)
        {
            return false;
        }
        return InstallInlinePatch(patch.Target, patch.HookEntry, patch.OriginalBytes);
    }

    void RemoveNtInlineHook(const NtHookPatch &patch) noexcept
    {
        if (patch.Target == nullptr || patch.OriginalBytes == nullptr)
        {
            return;
        }
        RemoveInlinePatch(patch.Target, patch.OriginalBytes);
    }

    bool CheckNtInlineHook(const NtHookPatch &patch) noexcept
    {
        return CheckInlinePatch(patch.Target, patch.HookEntry);
    }
} // namespace IX_NT_METHODS
