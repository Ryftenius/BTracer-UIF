#include "Core/runner_console.h"

#include <mutex>

namespace skugga::injector
{
    bool g_ConsoleColorEnabled = false;
    namespace
    {
        std::mutex g_ConsoleWriteMutex;
    }

    const char *AnsiForColor(LogColor color) noexcept
    {
        switch (color)
        {
        case LogColor::Info:
            return "\x1b[36m";
        case LogColor::Smart:
            return "\x1b[96m";
        case LogColor::Alert:
            return "\x1b[93m";
        case LogColor::Suspicious:
            return "\x1b[91m";
        case LogColor::Remote:
            return "\x1b[94m";
        case LogColor::RemoteRisk:
            return "\x1b[35m";
        case LogColor::Success:
            return "\x1b[92m";
        case LogColor::Warning:
            return "\x1b[33m";
        case LogColor::Error:
            return "\x1b[31m";
        case LogColor::Muted:
            return "\x1b[90m";
        case LogColor::Stack:
            return "\x1b[37m";
        case LogColor::Lifecycle:
            return "\x1b[95m";
        default:
            return "";
        }
    }

    bool StdoutIsConsole() noexcept
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output == nullptr || output == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        DWORD mode = 0;
        if (!GetConsoleMode(output, &mode))
        {
            return false;
        }

        DWORD desired = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (SetConsoleMode(output, desired))
        {
            return true;
        }
        return GetConsoleMode(output, &mode) != FALSE;
    }

    void ConfigureConsoleColor(ConsoleColorMode mode) noexcept
    {
        if (mode == ConsoleColorMode::Never)
        {
            g_ConsoleColorEnabled = false;
            return;
        }
        if (mode == ConsoleColorMode::Always)
        {
            g_ConsoleColorEnabled = true;
            (void)StdoutIsConsole();
            return;
        }
        g_ConsoleColorEnabled = StdoutIsConsole();
    }

    void BeginColor(LogColor color) noexcept
    {
        if (!g_ConsoleColorEnabled || color == LogColor::Default)
        {
            return;
        }
        std::fputs(AnsiForColor(color), stdout);
    }

    void EndColor(LogColor color) noexcept
    {
        if (!g_ConsoleColorEnabled || color == LogColor::Default)
        {
            return;
        }
        std::fputs("\x1b[0m", stdout);
    }

    void ColorPrintf(LogColor color, const char *format, ...)
    {
        char line[16384]{};
        va_list args;
        va_start(args, format);
        (void)vsnprintf(line, sizeof(line), format, args);
        va_end(args);

        std::lock_guard<std::mutex> lock(g_ConsoleWriteMutex);
        const char *tagEnd = line[0] == '[' ? std::strchr(line, ']') : nullptr;
        if (tagEnd != nullptr)
        {
            const std::size_t tagLength = static_cast<std::size_t>(tagEnd - line + 1);
            BeginColor(color);
            (void)std::fwrite(line, 1, tagLength, stdout);
            EndColor(color);
            std::fputs(line + tagLength, stdout);
            return;
        }

        BeginColor(color);
        std::fputs(line, stdout);
        EndColor(color);
    }

    void ColorWprintf(LogColor color, const wchar_t *format, ...)
    {
        BeginColor(color);
        va_list args;
        va_start(args, format);
        std::vwprintf(format, args);
        va_end(args);
        EndColor(color);
    }

    void TaggedPrintf(LogColor color, const char *tag, const char *format, ...)
    {
        std::lock_guard<std::mutex> lock(g_ConsoleWriteMutex);
        BeginColor(color);
        std::fputs(tag, stdout);
        EndColor(color);
        va_list args;
        va_start(args, format);
        std::vprintf(format, args);
        va_end(args);
    }

    void FormatReadyComponents(DWORD mask, char *out, std::size_t outChars) noexcept
    {
        if (out == nullptr || outChars == 0)
        {
            return;
        }
        out[0] = '\0';
        const struct
        {
            DWORD Flag;
            const char *Name;
        } components[] = {
            {SKUGGA_IPC_HOOK_READY_FLAG_IPC_CONNECTED, "ipc"},
            {SKUGGA_IPC_HOOK_READY_FLAG_WINSOCK, "winsock"},
            {SKUGGA_IPC_HOOK_READY_FLAG_NT, "nt"},
            {SKUGGA_IPC_HOOK_READY_FLAG_KI, "ki"},
            {SKUGGA_IPC_HOOK_READY_FLAG_MODULE, "module"},
        };
        for (const auto &component : components)
        {
            if ((mask & component.Flag) == 0)
            {
                continue;
            }
            if (out[0] != '\0')
            {
                (void)StringCchCatA(out, outChars, ",");
            }
            (void)StringCchCatA(out, outChars, component.Name);
        }
        if (out[0] == '\0')
        {
            (void)StringCchCopyA(out, outChars, "none");
        }
    }

} // namespace skugga::injector
