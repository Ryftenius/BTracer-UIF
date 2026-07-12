#include "Launch/injection.h"
#include "Core/runner_console.h"
#include "Diagnostics/diagnostics.h"
#include "Policy/option_parsing.h"

#include <limits>

namespace blind::injector {
bool QueryPortableExecutableMachine(const std::wstring &path,
                                    WORD &machine) noexcept {
  machine = IMAGE_FILE_MACHINE_UNKNOWN;
  HANDLE file =
      CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  IMAGE_DOS_HEADER dos{};
  DWORD read = 0;
  LARGE_INTEGER ntOffset{};
  ntOffset.QuadPart = 0;
  SetLastError(ERROR_SUCCESS);
  bool ok = ReadFile(file, &dos, sizeof(dos), &read, nullptr) &&
            read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
            dos.e_lfanew > 0;
  if (ok) {
    ntOffset.QuadPart = dos.e_lfanew;
    ok = SetFilePointerEx(file, ntOffset, nullptr, FILE_BEGIN) != FALSE;
  }
  struct {
    DWORD Signature;
    IMAGE_FILE_HEADER Header;
  } nt{};
  if (ok) {
    read = 0;
    ok = ReadFile(file, &nt, sizeof(nt), &read, nullptr) &&
         read == sizeof(nt) && nt.Signature == IMAGE_NT_SIGNATURE;
  }
  const DWORD queryError = ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(file);
  if (ok) {
    machine = nt.Header.Machine;
  } else {
    SetLastError(queryError != ERROR_SUCCESS ? queryError
                                             : ERROR_BAD_EXE_FORMAT);
  }
  return ok;
}

bool RelaunchForTargetArchitecture(int argc, wchar_t **argv,
                                   const std::wstring &targetPath,
                                   int &exitCode) {
  exitCode = 0;
  WORD targetMachine = IMAGE_FILE_MACHINE_UNKNOWN;
  if (!QueryPortableExecutableMachine(targetPath, targetMachine)) {
    ColorWprintf(LogColor::Error,
                 L"[blind] cannot read target architecture: %ls error=%lu\n",
                 targetPath.c_str(), GetLastError());
    exitCode = 4;
    return true;
  }

#if defined(_WIN64)
  constexpr WORD runnerMachine = IMAGE_FILE_MACHINE_AMD64;
  constexpr const wchar_t *helperPlatform = L"Win32";
#else
  constexpr WORD runnerMachine = IMAGE_FILE_MACHINE_I386;
  constexpr const wchar_t *helperPlatform = L"x64";
#endif
  if (targetMachine == runnerMachine) {
    return false;
  }
  if (targetMachine != IMAGE_FILE_MACHINE_I386 &&
      targetMachine != IMAGE_FILE_MACHINE_AMD64) {
    ColorWprintf(LogColor::Error,
                 L"[blind] unsupported target machine=0x%04X\n",
                 static_cast<unsigned>(targetMachine));
    SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
    exitCode = 4;
    return true;
  }

  wchar_t dispatched[8]{};
  if (GetEnvironmentVariableW(L"BLIND_ARCH_DISPATCHED", dispatched,
                              RTL_NUMBER_OF(dispatched)) != 0) {
    ColorWprintf(LogColor::Error,
                 L"[blind] architecture helper mismatch target=0x%04X "
                 L"runner=0x%04X\n",
                 targetMachine, runnerMachine);
    SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
    exitCode = 4;
    return true;
  }

  const std::wstring platformRoot =
      BLIND_SUPPORT::DirectoryOf(ModuleDirectory().c_str());
  const std::wstring helperDirectory =
      BLIND_SUPPORT::JoinPath(platformRoot, helperPlatform);
  const std::wstring helper =
      BLIND_SUPPORT::JoinPath(helperDirectory, L"BlindRunner.exe");
  if (!FileExists(helper)) {
    ColorWprintf(LogColor::Error,
                 L"[blind] missing %ls architecture helper: %ls\n",
                 helperPlatform, helper.c_str());
    SetLastError(ERROR_FILE_NOT_FOUND);
    exitCode = 4;
    return true;
  }

  std::wstring commandLine = QuoteCommandLineArgument(helper);
  for (int i = 1; i < argc; ++i) {
    commandLine.push_back(L' ');
    commandLine += QuoteCommandLineArgument(argv[i]);
  }

  STARTUPINFOW startup{};
  PROCESS_INFORMATION process{};
  startup.cb = sizeof(startup);
  (void)SetEnvironmentVariableW(L"BLIND_ARCH_DISPATCHED", L"1");
  BOOL created =
      CreateProcessW(helper.c_str(), commandLine.data(), nullptr, nullptr,
                     FALSE, 0, nullptr, nullptr, &startup, &process);
  (void)SetEnvironmentVariableW(L"BLIND_ARCH_DISPATCHED", nullptr);
  if (!created) {
    ColorWprintf(LogColor::Error,
                 L"[blind] architecture helper launch failed error=%lu\n",
                 GetLastError());
    exitCode = 4;
    return true;
  }

  ColorWprintf(LogColor::Lifecycle,
               L"[blind] target machine=%ls dispatch=%ls\n",
               targetMachine == IMAGE_FILE_MACHINE_I386 ? L"x86" : L"x64",
               helper.c_str());
  DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
  DWORD helperExit = 4;
  if (wait != WAIT_OBJECT_0 ||
      !GetExitCodeProcess(process.hProcess, &helperExit)) {
    helperExit = 4;
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  exitCode = static_cast<int>(helperExit);
  return true;
}

std::wstring WideBaseName(const std::wstring &path) {
  std::size_t pos = path.find_last_of(L"\\/");
  return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

bool GetRemoteModuleBase(DWORD pid, const std::wstring &baseName,
                         UINT64 &base) {
  base = 0;
  HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool found = false;
  if (Module32FirstW(snapshot, &entry)) {
    do {
      if (_wcsicmp(entry.szModule, baseName.c_str()) == 0) {
        base = reinterpret_cast<UINT64>(entry.modBaseAddr);
        found = true;
        break;
      }
      entry.dwSize = sizeof(entry);
    } while (Module32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return found;
}

bool InjectDllIntoChild(ServerContext &ctx, HANDLE process,
                        const std::wstring &dllPath) {
  if (dllPath.size() >=
      (std::numeric_limits<SIZE_T>::max() / sizeof(wchar_t)) - 1u) {
    std::printf("[blind] DLL path is too long to inject safely\n");
    return false;
  }

  SIZE_T bytes = (dllPath.size() + 1u) * sizeof(wchar_t);
  void *remotePath = VirtualAllocEx(process, nullptr, bytes,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (remotePath == nullptr) {
    std::printf("[blind] VirtualAllocEx failed gle=%lu\n", GetLastError());
    return false;
  }

  bool ok = false;
  SIZE_T written = 0;
  if (WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes,
                         &written) &&
      written == bytes) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto loadLibraryW = kernel32 != nullptr
                            ? reinterpret_cast<LPTHREAD_START_ROUTINE>(
                                  GetProcAddress(kernel32, "LoadLibraryW"))
                            : nullptr;
    if (loadLibraryW == nullptr) {
      std::printf("[blind] LoadLibraryW resolution failed gle=%lu\n",
                  GetLastError());
    }
    HANDLE thread = loadLibraryW != nullptr
                        ? CreateRemoteThread(process, nullptr, 0, loadLibraryW,
                                             remotePath, 0, nullptr)
                        : nullptr;
    if (thread != nullptr) {
      DWORD wait = WaitForSingleObject(thread, kInjectTimeoutMs);
      DWORD exitCode = 0;
      if (wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &exitCode) &&
          exitCode != 0) {
        ok = true;
      } else {
        const DWORD injectionError =
            (wait == WAIT_TIMEOUT) ? ERROR_TIMEOUT : ERROR_DLL_INIT_FAILED;
        std::printf("[blind] LoadLibrary remote thread failed wait=%lu "
                    "exit=0x%08lX error=%lu\n",
                    wait, exitCode, injectionError);
        SetLastError(injectionError);
      }
      CloseHandle(thread);
    } else {
      std::printf("[blind] CreateRemoteThread failed gle=%lu\n",
                  GetLastError());
    }
  } else {
    std::printf("[blind] WriteProcessMemory failed gle=%lu\n", GetLastError());
  }

  DWORD injectionError = ok ? ERROR_SUCCESS : GetLastError();
  VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
  if (!ok) {
    SetLastError(injectionError != ERROR_SUCCESS ? injectionError
                                                 : ERROR_DLL_INIT_FAILED);
  }
  HostDebugLog(ctx, "loadlibrary injection complete ok=%u", ok ? 1u : 0u);
  return ok;
}
} // namespace blind::injector
