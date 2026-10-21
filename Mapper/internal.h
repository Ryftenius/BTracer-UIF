#pragma once

#include "mapper.h"

#include "Core/runner_console.h"
#include "Core/runner_core.h"
#include "Diagnostics/diagnostics.h"
#include "Launch/injection.h"

namespace skugga::mapper
{
    using namespace skugga::injector;

#if defined(_WIN64)
    using NativeImageNtHeaders = IMAGE_NT_HEADERS64;
    using NativeImageThunkData = IMAGE_THUNK_DATA64;
    using NativeImageTlsDirectory = IMAGE_TLS_DIRECTORY64;
    inline constexpr WORD kNativeOptionalHeaderMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    inline constexpr WORD kNativeMachine = IMAGE_FILE_MACHINE_AMD64;
#else
    using NativeImageNtHeaders = IMAGE_NT_HEADERS32;
    using NativeImageThunkData = IMAGE_THUNK_DATA32;
    using NativeImageTlsDirectory = IMAGE_TLS_DIRECTORY32;
    inline constexpr WORD kNativeOptionalHeaderMagic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    inline constexpr WORD kNativeMachine = IMAGE_FILE_MACHINE_I386;
#endif

    struct MappedImage
    {
        std::vector<BYTE> Image;
        UINT64 PreferredBase = 0;
        DWORD SizeOfImage = 0;
        DWORD SizeOfHeaders = 0;
        DWORD EntryPointRva = 0;
    };

    struct BootstrapData
    {
        ULONG_PTR ImageBase = 0;
        ULONG_PTR EntryPoint = 0;
        ULONG_PTR TlsCallbacks = 0;
        ULONG_PTR RtlAddFunctionTable = 0;
        ULONG_PTR ExceptionTable = 0;
        UINT32 ExceptionCount = 0;
        UINT32 Status = 0;
        ULONG_PTR EntryResult = 0;
    };

#if defined(_WIN64)
    static_assert(offsetof(BootstrapData, Status) == 0x2C, "manual-map bootstrap layout drifted");
    static_assert(offsetof(BootstrapData, EntryResult) == 0x30, "manual-map bootstrap layout drifted");
#else
    static_assert(offsetof(BootstrapData, Status) == 0x18, "manual-map bootstrap layout drifted");
    static_assert(offsetof(BootstrapData, EntryResult) == 0x1C, "manual-map bootstrap layout drifted");
#endif

    inline constexpr DWORD kBootstrapStarted = 1;
    inline constexpr DWORD kBootstrapSucceeded = 2;
    inline constexpr DWORD kBootstrapRtlAddFunctionTableFailed = 0x80000001u;
    inline constexpr DWORD kBootstrapEntryPointFailed = 0x80000002u;

    bool Fail(ServerContext &ctx, const char *message);
    bool FailLastError(ServerContext &ctx, const char *operation, DWORD gle = GetLastError());
    bool ReadFileBytes(const std::wstring &path, std::vector<BYTE> &out);
    bool ImageRangeValid(std::size_t imageSize, DWORD rva, std::size_t size) noexcept;

    template <typename T> T *ImageRvaPtr(std::vector<BYTE> &image, DWORD rva)
    {
        if (!ImageRangeValid(image.size(), rva, sizeof(T)))
        {
            return nullptr;
        }
        return reinterpret_cast<T *>(image.data() + rva);
    }

    BYTE *ImageRvaBytes(std::vector<BYTE> &image, DWORD rva, std::size_t size);
    const char *ImageRvaString(std::vector<BYTE> &image, DWORD rva);
    NativeImageNtHeaders *ImageNtHeaders(std::vector<BYTE> &image);

    bool PrepareMappedImage(ServerContext &ctx, const std::wstring &dllPath, MappedImage &mapped);
    bool ApplyRelocations(ServerContext &ctx, MappedImage &mapped, UINT64 remoteBase);
    HMODULE LoadLocalImportModule(const char *name);
    bool FindRemoteMappedImageBaseByName(HANDLE process, const std::wstring &baseName, UINT64 &base);
    bool ResolveRemoteAddressForLocalProc(HANDLE process, FARPROC localProc, UINT64 &remoteAddress,
                                          std::wstring *moduleNameOut);
    bool ResolveImports(ServerContext &ctx, HANDLE process, MappedImage &mapped);
    DWORD ProtectionFromSectionCharacteristics(DWORD characteristics) noexcept;
    bool ProtectMappedImage(ServerContext &ctx, HANDLE process, UINT64 remoteBase, MappedImage &mapped);
    UINT64 GetTlsCallbacks(MappedImage &mapped);
    bool ResolveRemoteRtlAddFunctionTable(ServerContext &ctx, HANDLE process, UINT64 &remoteAddress);
    bool RunBootstrap(ServerContext &ctx, HANDLE process, UINT64 remoteBase, MappedImage &mapped);
} // namespace skugga::mapper
