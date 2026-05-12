#include "interpreter.hpp"

bool removeBreakpoint(const uint64_t& address) {
    breakpointMutex.lock();

    bool success = false;
    if (breakpointLines.empty()) {
        breakpointMutex.unlock();
        return success;
    }

    const auto it = std::ranges::find(breakpointLines, addressLineNoMap[address]);
    if  (it != breakpointLines.end()) {
        icicle_remove_breakpoint(icicle, address);
        breakpointLines.erase(it);
        success = true;
    }

    breakpointMutex.unlock();
    return success;
}

bool removeBreakpointFromLineNo(const uint64_t& lineNo) {
    breakpointMutex.lock();
    bool success = false;

    if (isSilentBreakpoint(lineNo))
    {
        // We don't need to remove silent breakpoints
        LOG_ALERT("Attempt to remove a silent breakpoint. Ignoring.");
        return true;
    }

    if (breakpointLines.empty()) {
        breakpointMutex.unlock();
        return success;
    }

    const auto it = std::ranges::find(breakpointLines, lineNo);
    size_t size;
    const uint64_t* bpList = icicle_breakpoint_list(icicle, &size);

    if (bpList)
    {
        for (size_t i = 0; i < size; ++i) {
            if (bpList[i] == lineNoToAddress(lineNo)) {
                if  (it != breakpointLines.end()) {
                    icicle_remove_breakpoint(icicle, lineNoToAddress(lineNo));
                    breakpointLines.erase(it);
                    success = true;
                    LOG_DEBUG("Removed a breakpoint at lineNo " << lineNo);
                    editor->RemoveHighlight(lineNo);
                }
                break;
            }
        }
    }


    breakpointMutex.unlock();

    return success;
}

bool isSilentBreakpoint(const uint64_t& lineNo)
{
    if (icicle == nullptr)
    {
        return false;
    }

    size_t outSize{};
    uint64_t* breakpointList = icicle_breakpoint_list(icicle, &outSize);
    if (breakpointList == nullptr)
    {
        return false;
    }

    for (size_t i = 0; i < outSize; i++)
    {
        if (breakpointList[i] == lineNoToAddress(lineNo))
        {
            if (std::ranges::find(breakpointLines, lineNo) == breakpointLines.end())
            {
                icicle_breakpoint_list_free(breakpointList, outSize);
                // a silent breakpoint is a breakpoint which was internally added by
                // our code and not by the user
                return true;
            }

            icicle_breakpoint_list_free(breakpointList, outSize);
            return false;
        }
    }

    icicle_breakpoint_list_free(breakpointList, outSize);
    return false;
}

bool addBreakpoint(const uint64_t& address, const bool& silent)
{
    if (icicle == nullptr)
    {
        return false;
    }

    if (icicle_add_breakpoint(icicle, address))
    {
       return true;
    }

    return false;
}

bool addBreakpointToLine(const uint64_t& lineNo, const bool& silent)
{
    const bool skipCheck = icicle == nullptr;

    if (!addBreakpoint(lineNoToAddress(lineNo + 1), silent) && !skipCheck)
    {
        return false;
    }

    if (!silent)
    {
        breakpointLines.push_back(lineNo + 1);
        editor->HighlightBreakpoints(lineNo);
    }

    return true;
}
