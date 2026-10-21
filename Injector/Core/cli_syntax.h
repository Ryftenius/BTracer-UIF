#pragma once
#include <string>
#include <vector>
#include <cwchar>

// Normalize only known switches. Everything after -- belongs to the target.
inline std::vector<std::wstring> NormalizeSkuggaArgs(int argc, wchar_t **argv)
{
    std::vector<std::wstring> out;
    bool literal = false;
    for (int i = 0; i < argc; ++i)
    {
        std::wstring value = argv[i];
        if (i == 0 || literal)
        {
            out.push_back(value);
            continue;
        }
        if (value == L"--")
        {
            literal = true;
            out.push_back(value);
            continue;
        }
        if (value.size() > 1 && value[0] == L'/' && value != L"/?")
        {
            const auto colon = value.find(L':');
            const auto name = value.substr(1, colon == std::wstring::npos ? colon : colon - 1);
            const std::wstring known = L"|api|group|stack|registers|quiet|loader|deny|timeout|behavior|help|version|no-"
                                       L"launch-gate|symbols|verbose|debug|raw|pipe|include-internals|";
            if (known.find(L"|" + name + L"|") != std::wstring::npos)
            {
                if (name == L"behavior" && colon != std::wstring::npos)
                {
                    out.push_back(L"--behavior=" + value.substr(colon + 1));
                    continue;
                }
                out.push_back(L"--" + name);
                if (colon != std::wstring::npos)
                    out.push_back(value.substr(colon + 1));
                continue;
            }
        }
        out.push_back(value);
    }
    return out;
}
