#include "Telemetry/smart_summary.h"
#include "Core/runner_console.h"
#include "Telemetry/event_formatting.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/stack_address.h"

namespace skugga::injector
{
    void PrintSmartSummary(ServerContext &ctx, bool finalSummary)
    {
        if (!ctx.SmartMode)
        {
            return;
        }

        std::printf("\n");
        TaggedPrintf(LogColor::Smart, "[skugga:behavior]", " %s summary\n", finalSummary ? "final" : "periodic");
        std::printf("  scope       targets=%zu regions=%zu protect_groups=%zu "
                    "thread_starts=%zu handles=%zu\n",
                    ctx.SmartTargets.size(), ctx.SmartRegions.size(), ctx.SmartProtectGroups.size(),
                    ctx.SmartThreadGroups.size(), ctx.SmartHandleGroups.size());

        for (const auto &target : ctx.SmartTargets)
        {
            std::string label = TargetLabel(ctx, ctx.ChildProcessId, target.TargetPid);
            UINT32 regionCount = 0;
            for (const auto &region : ctx.SmartRegions)
            {
                if (region.TargetPid == target.TargetPid)
                {
                    regionCount += 1;
                }
            }

            char allocText[32]{};
            char mapText[32]{};
            char queryText[32]{};
            char readText[32]{};
            char writeText[32]{};
            char rwxText[32]{};
            FormatBytes(target.AllocBytes, allocText, RTL_NUMBER_OF(allocText));
            FormatBytes(target.MapBytes, mapText, RTL_NUMBER_OF(mapText));
            FormatBytes(target.QueryInfoBytes, queryText, RTL_NUMBER_OF(queryText));
            FormatBytes(target.ReadBytes, readText, RTL_NUMBER_OF(readText));
            FormatBytes(target.WriteBytes, writeText, RTL_NUMBER_OF(writeText));
            FormatBytes(target.RwxBytes, rwxText, RTL_NUMBER_OF(rwxText));
            TaggedPrintf(SmartTargetColor(ctx, target), "[skugga:target]",
                         " %s  risk=%s\n"
                         "  memory      allocs=%lu total=%s "
                         "pages=%llu maps=%lu mapped=%s "
                         "regions=%lu protects=%lu queries=%lu query_info=%s reads=%lu "
                         "read=%s writes=%lu "
                         "written=%s\n"
                         "  activity    process_opens=%lu thread_opens=%lu rwx=%s "
                         "threads=%lu apc=%lu\n",
                         label.c_str(), SmartTargetRisk(ctx, target), static_cast<unsigned long>(target.AllocCount),
                         allocText, static_cast<unsigned long long>(PageCount(target.AllocBytes)),
                         static_cast<unsigned long>(target.MapCount), mapText, static_cast<unsigned long>(regionCount),
                         static_cast<unsigned long>(target.ProtectCount), static_cast<unsigned long>(target.QueryCount),
                         queryText, static_cast<unsigned long>(target.ReadCount), readText,
                         static_cast<unsigned long>(target.WriteCount), writeText,
                         static_cast<unsigned long>(target.OpenProcessCount),
                         static_cast<unsigned long>(target.OpenThreadCount), rwxText,
                         static_cast<unsigned long>(target.ThreadCount), static_cast<unsigned long>(target.ApcCount));

            std::vector<const SmartHandleGroup *> handleGroups;
            for (const auto &group : ctx.SmartHandleGroups)
            {
                if (group.TargetPid == target.TargetPid)
                {
                    handleGroups.push_back(&group);
                }
            }
            std::sort(handleGroups.begin(), handleGroups.end(),
                      [](const SmartHandleGroup *left, const SmartHandleGroup *right)
                      {
                          if (left->Count != right->Count)
                          {
                              return left->Count > right->Count;
                          }
                          return left->DesiredAccess > right->DesiredAccess;
                      });

            if (!handleGroups.empty())
            {
                std::printf("  handles\n");
            }
            UINT32 printedHandles = 0;
            for (const auto *group : handleGroups)
            {
                if (printedHandles >= 5)
                {
                    break;
                }

                char accessText[320]{};
                char callerText[256]{};
                char startText[256]{};
                char startRegionText[64]{};
                char evidenceText[640]{};
                if (group->Kind == SmartHandleKind::Process)
                {
                    FormatProcessAccess(group->DesiredAccess, accessText, RTL_NUMBER_OF(accessText));
                    (void)StringCchCopyA(startText, RTL_NUMBER_OF(startText), "-");
                    (void)StringCchCopyA(startRegionText, RTL_NUMBER_OF(startRegionText), "-");
                }
                else
                {
                    FormatThreadAccess(group->DesiredAccess, accessText, RTL_NUMBER_OF(accessText));
                    if (group->ThreadStart != 0)
                    {
                        FormatSmartAddress(ctx, group->TargetPid, group->ThreadStart, startText,
                                           RTL_NUMBER_OF(startText));
                        FormatVadRegion(group->ThreadVad, startRegionText, RTL_NUMBER_OF(startRegionText));
                    }
                    else
                    {
                        (void)StringCchCopyA(startText, RTL_NUMBER_OF(startText), "unknown");
                        (void)StringCchCopyA(startRegionText, RTL_NUMBER_OF(startRegionText), "unknown");
                    }
                }
                if (ctx.ResolveSymbols)
                {
                    FormatChildSymbolAddress(ctx, group->Caller, callerText, RTL_NUMBER_OF(callerText));
                }
                else
                {
                    FormatChildAddress(ctx, group->Caller, callerText, RTL_NUMBER_OF(callerText));
                }
                FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, group->CallerVad, group->PrivateFrame,
                                          group->PrivateFrameVad, group->RwxFrame, group->RwxFrameVad, evidenceText,
                                          RTL_NUMBER_OF(evidenceText));
                TaggedPrintf(SmartHandleColor(ctx, *group), "    [handle]",
                             " kind=%s target=%s count=%lu failed=%lu risk=%s\n"
                             "      access=%s status=0x%08lX handle=0x%llX "
                             "object=0x%llX tid=%lu\n"
                             "      start=%s region=%s caller=%s stack=0x%llX%s\n",
                             group->Kind == SmartHandleKind::Process ? "process" : "thread", label.c_str(),
                             static_cast<unsigned long>(group->Count), static_cast<unsigned long>(group->FailedCount),
                             SmartHandleRisk(*group), accessText, static_cast<unsigned long>(group->LastStatus),
                             static_cast<unsigned long long>(group->LastHandle),
                             static_cast<unsigned long long>(group->LastObject),
                             static_cast<unsigned long>(group->TargetTid), startText, startRegionText, callerText,
                             static_cast<unsigned long long>(group->StackHash), evidenceText);
                PrintSmartStackSample(ctx, "handle", group->Kind == SmartHandleKind::Process ? "pid" : "tid",
                                      group->Kind == SmartHandleKind::Process ? group->TargetPid : group->TargetTid,
                                      group->TargetPid, group->StackHash, group->Stack);
                printedHandles += 1;
            }
            if (handleGroups.size() > printedHandles)
            {
                std::printf("    ... %zu additional handle group(s) omitted\n", handleGroups.size() - printedHandles);
            }

            std::vector<const SmartProtectGroup *> protectGroups;
            for (const auto &group : ctx.SmartProtectGroups)
            {
                if (group.TargetPid == target.TargetPid)
                {
                    protectGroups.push_back(&group);
                }
            }
            std::sort(protectGroups.begin(), protectGroups.end(),
                      [](const SmartProtectGroup *left, const SmartProtectGroup *right)
                      {
                          if (left->Count != right->Count)
                          {
                              return left->Count > right->Count;
                          }
                          return left->FirstBase < right->FirstBase;
                      });

            if (!protectGroups.empty())
            {
                std::printf("  protection transitions\n");
            }
            UINT32 printedProtectGroups = 0;
            for (const auto *group : protectGroups)
            {
                if (printedProtectGroups >= 5)
                {
                    break;
                }

                char oldText[32]{};
                char newText[32]{};
                char sizeText[32]{};
                char firstText[256]{};
                char lastText[256]{};
                char callerText[256]{};
                char evidenceText[640]{};
                FormatProtect(group->OldProtect, oldText, RTL_NUMBER_OF(oldText));
                FormatProtect(group->NewProtect, newText, RTL_NUMBER_OF(newText));
                FormatBytes(group->Size, sizeText, RTL_NUMBER_OF(sizeText));
                FormatSmartAddress(ctx, group->TargetPid, group->FirstBase, firstText, RTL_NUMBER_OF(firstText));
                FormatSmartAddress(ctx, group->TargetPid, group->LastBase, lastText, RTL_NUMBER_OF(lastText));
                if (ctx.ResolveSymbols)
                {
                    FormatChildSymbolAddress(ctx, group->Caller, callerText, RTL_NUMBER_OF(callerText));
                }
                else
                {
                    FormatChildAddress(ctx, group->Caller, callerText, RTL_NUMBER_OF(callerText));
                }
                FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, group->CallerVad, group->PrivateFrame,
                                          group->PrivateFrameVad, group->RwxFrame, group->RwxFrameVad, evidenceText,
                                          RTL_NUMBER_OF(evidenceText));
                TaggedPrintf(SmartProtectColor(*group), "    [protect]",
                             " %s -> %s  count=%lu pages=%llu size=%s risk=%s\n"
                             "      target=%s first=%s last=%s span=0x%llX-0x%llX\n"
                             "      origin=%s vad=%s/%s stack=0x%llX rwx=%lu%s\n",
                             oldText, newText, static_cast<unsigned long>(group->Count),
                             static_cast<unsigned long long>(group->Pages), sizeText, SmartProtectRisk(*group),
                             label.c_str(), firstText, lastText, static_cast<unsigned long long>(group->MinBase),
                             static_cast<unsigned long long>(group->MaxBase), callerText,
                             group->Vad.Valid ? MemoryStateName(group->Vad.State) : "unknown",
                             group->Vad.Valid ? MemoryTypeName(group->Vad.Type) : "unknown",
                             static_cast<unsigned long long>(group->StackHash),
                             static_cast<unsigned long>(group->RwxCount), evidenceText);
                PrintSmartStackSample(ctx, "protect", "first", group->FirstBase, group->TargetPid, group->StackHash,
                                      group->Stack);
                printedProtectGroups += 1;
            }
            if (protectGroups.size() > printedProtectGroups)
            {
                std::printf("    ... %zu additional transition group(s) omitted\n",
                            protectGroups.size() - printedProtectGroups);
            }

            std::vector<const SmartMemoryRegion *> regions;
            for (const auto &region : ctx.SmartRegions)
            {
                if (region.TargetPid == target.TargetPid)
                {
                    regions.push_back(&region);
                }
            }
            std::sort(regions.begin(), regions.end(),
                      [](const SmartMemoryRegion *left, const SmartMemoryRegion *right)
                      {
                          UINT64 leftActivity = static_cast<UINT64>(left->AllocCount) + left->MapCount +
                                                left->ProtectCount + left->QueryCount + left->ReadCount +
                                                left->WriteCount;
                          UINT64 rightActivity = static_cast<UINT64>(right->AllocCount) + right->MapCount +
                                                 right->ProtectCount + right->QueryCount + right->ReadCount +
                                                 right->WriteCount;
                          if (leftActivity != rightActivity)
                          {
                              return leftActivity > rightActivity;
                          }
                          if (left->Size != right->Size)
                          {
                              return left->Size > right->Size;
                          }
                          return left->Base < right->Base;
                      });

            if (!regions.empty())
            {
                std::printf("  regions of interest\n");
            }
            UINT32 printedRegions = 0;
            for (const auto *region : regions)
            {
                if (printedRegions >= 5)
                {
                    break;
                }

                char sizeText[32]{};
                char protectText[32]{};
                char allocProtectText[32]{};
                char allocTypeText[64]{};
                char callerText[256]{};
                char regionReadText[32]{};
                char writtenText[32]{};
                char evidenceText[640]{};
                FormatBytes(region->Size, sizeText, RTL_NUMBER_OF(sizeText));
                FormatProtect(region->Protect, protectText, RTL_NUMBER_OF(protectText));
                FormatProtect(region->AllocationProtect, allocProtectText, RTL_NUMBER_OF(allocProtectText));
                FormatAllocationType(region->AllocationType, allocTypeText, RTL_NUMBER_OF(allocTypeText));
                if (ctx.ResolveSymbols)
                {
                    FormatChildSymbolAddress(ctx, region->Caller, callerText, RTL_NUMBER_OF(callerText));
                }
                else
                {
                    FormatChildAddress(ctx, region->Caller, callerText, RTL_NUMBER_OF(callerText));
                }
                FormatBytes(region->TotalRead, regionReadText, RTL_NUMBER_OF(regionReadText));
                FormatBytes(region->TotalWritten, writtenText, RTL_NUMBER_OF(writtenText));
                FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, region->CallerVad, region->PrivateFrame,
                                          region->PrivateFrameVad, region->RwxFrame, region->RwxFrameVad, evidenceText,
                                          RTL_NUMBER_OF(evidenceText));
                TaggedPrintf(
                    SmartRegionColor(ctx, *region), "    [region]",
                    " base=0x%llX size=%s pages=%llu protect=%s risk=%s\n"
                    "      target=%s activity=alloc:%lu map:%lu protect:%lu flip:%lu "
                    "query:%lu read:%lu/%s write:%lu/%s\n"
                    "      vad=%s/%s alloc=%s/%s last_query=%s(%lu)\n"
                    "      origin=%s stack=0x%llX sequence=%s%s\n",
                    static_cast<unsigned long long>(region->Base), sizeText,
                    static_cast<unsigned long long>(PageCount(region->Size)), protectText, SmartRegionRisk(*region),
                    label.c_str(), static_cast<unsigned long>(region->AllocCount),
                    static_cast<unsigned long>(region->MapCount), static_cast<unsigned long>(region->ProtectCount),
                    static_cast<unsigned long>(region->FlipCount), static_cast<unsigned long>(region->QueryCount),
                    static_cast<unsigned long>(region->ReadCount), regionReadText,
                    static_cast<unsigned long>(region->WriteCount), writtenText, MemoryStateName(region->State),
                    MemoryTypeName(region->Type), allocProtectText, allocTypeText,
                    MemoryInformationClassName(region->LastQueryClass),
                    static_cast<unsigned long>(region->LastQueryClass), callerText,
                    static_cast<unsigned long long>(region->StackHash),
                    region->ProtectSequence[0] != '\0' ? region->ProtectSequence : "-", evidenceText);
                PrintSmartStackSample(ctx, "region", "base", region->Base, region->TargetPid, region->StackHash,
                                      region->Stack);
                printedRegions += 1;
            }
            if (regions.size() > printedRegions)
            {
                std::printf("    ... %zu additional region(s) omitted\n", regions.size() - printedRegions);
            }
        }

        if (!ctx.SmartThreadGroups.empty())
        {
            std::printf("  thread starts\n");
        }
        UINT32 printedThreads = 0;
        for (const auto &group : ctx.SmartThreadGroups)
        {
            if (printedThreads >= 5)
            {
                break;
            }
            std::string label = TargetLabel(ctx, ctx.ChildProcessId, group.TargetPid);
            char startText[256]{};
            char callerText[256]{};
            char protectText[32]{};
            char startRegionText[64]{};
            char evidenceText[640]{};
            FormatSmartAddress(ctx, group.TargetPid, group.Start, startText, RTL_NUMBER_OF(startText));
            if (ctx.ResolveSymbols)
            {
                FormatChildSymbolAddress(ctx, group.Caller, callerText, RTL_NUMBER_OF(callerText));
            }
            else
            {
                FormatChildAddress(ctx, group.Caller, callerText, RTL_NUMBER_OF(callerText));
            }
            FormatProtect(group.Vad.Protect, protectText, RTL_NUMBER_OF(protectText));
            FormatVadRegion(group.Vad, startRegionText, RTL_NUMBER_OF(startRegionText));
            FormatSmartEvidenceSuffix(ctx, ctx.ChildProcessId, group.CallerVad, group.PrivateFrame,
                                      group.PrivateFrameVad, group.RwxFrame, group.RwxFrameVad, evidenceText,
                                      RTL_NUMBER_OF(evidenceText));
            TaggedPrintf(SmartThreadColor(group), "    [thread]",
                         " start=%s target=%s count=%lu suspended=%lu risk=%s\n"
                         "      private=%u vad=%s/%s/%s region=%s\n"
                         "      origin=%s stack=0x%llX%s\n",
                         startText, label.c_str(), static_cast<unsigned long>(group.Count),
                         static_cast<unsigned long>(group.SuspendedCount), SmartThreadRisk(group),
                         group.PrivateStart ? 1u : 0u, group.Vad.Valid ? MemoryStateName(group.Vad.State) : "unknown",
                         group.Vad.Valid ? MemoryTypeName(group.Vad.Type) : "unknown", protectText, startRegionText,
                         callerText, static_cast<unsigned long long>(group.StackHash), evidenceText);
            PrintSmartStackSample(ctx, "thread", "start", group.Start, group.TargetPid, group.StackHash, group.Stack);
            printedThreads += 1;
        }
        if (ctx.SmartThreadGroups.size() > printedThreads)
        {
            std::printf("    ... %zu additional thread-start group(s) omitted\n",
                        ctx.SmartThreadGroups.size() - printedThreads);
        }
    }
    void MaybePrintSmartSummary(ServerContext &ctx)
    {
        if (!ctx.SmartMode || ctx.SmartSummaryIntervalMs == 0)
        {
            return;
        }
        DWORD now = GetTickCount();
        if (ctx.LastSmartSummaryTick == 0 || now - ctx.LastSmartSummaryTick >= ctx.SmartSummaryIntervalMs)
        {
            PrintSmartSummary(ctx, false);
            ctx.LastSmartSummaryTick = now;
        }
    }
} // namespace skugga::injector
