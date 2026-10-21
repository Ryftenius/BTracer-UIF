#pragma once

#include "../instrument/stacktrace.h"

namespace IX_STACK_FABRICATE
{
    void SanitizeSkuggaFrames(IC_STACKTRACE::Trace &trace) noexcept;
}
