#include "windows.hpp"

std::vector<MemRegionInfo> getMemoryMapping(Icicle* ic)
{
    size_t count;
    MemRegionInfo* memRegionInfoArray = icicle_mem_list_mapped(icicle, &count);
    
    std::vector<MemRegionInfo> memMapInfo;
    memMapInfo.reserve(count);

    for (size_t i = 0; i < count; i++) {
        memMapInfo.push_back(memRegionInfoArray[i]);
    }

    icicle_mem_list_mapped_free(memRegionInfoArray, count);
    return memMapInfo;
}

inline bool updateMemoryPermissions(Icicle* ic, const uint64_t startAddr, const uint64_t endAddr,
                                    const MemoryProtection newPerms)
{
    auto err = icicle_mem_protect(icicle, startAddr, endAddr - startAddr, newPerms);
    if (err != 0)
    {
        return false;
    }

    return true;
}

bool expandMemoryRegion(Icicle* ic, const uint64_t startAddr, uint64_t oldEndAddr, uint64_t newEndAddr,
                        const uint64_t oldSize, const MemoryProtection perms)
{
    if (!(perms & MemoryProtection::ReadWrite) && !(perms & MemoryProtection::ExecuteReadWrite))
    {
        LOG_ERROR("The memory region expansion process could not be completed because the memory region does not have read and write permissions.");
        return false;
    }

    if (startAddr > newEndAddr)
    {
        LOG_ERROR("The memory region expansion process failed because startAddr > newEndAddr");
        return false;
    }

    auto newSize = (newEndAddr - startAddr);

    if (((newSize % 4096) != 0))
    {
        LOG_ALERT("The new size requested for the memory region is not a multiple of 4096, rounding up...");
        tinyfd_messageBox(
            "Warning",
            "The new end address provided by you is not a multiple of the page size. The number will be rounded up to a multiple of 4KB.",
            "ok", "warning", 1);
        newEndAddr = (newEndAddr + 4095) & ~4095;
        newSize = newEndAddr - startAddr;
        LOG_INFO("Rounded up size is " << newSize);
    }

    VmSnapshot* tempMemSnapshot = icicle_vm_snapshot(ic);
    // maybe allocate a page?
    // const auto saved = static_cast<char*>(malloc(oldSize));
    // size_t outSize{};
    // auto oldData = icicle_mem_read(ic, startAddr, oldSize, &outSize);
    // if (outSize == 0)
    // {
    //     LOG_ERROR("Unable to read from the memory region for expansion.");
    //     icicle_vm_snapshot_free(tempMemSnapshot);
    //     return false;
    // }

    int err = icicle_mem_unmap(icicle, startAddr, oldSize);
    if (err != 0)
    {
        LOG_ERROR("Unable to unmap the memory region for expansion.");
        icicle_vm_snapshot_free(tempMemSnapshot);
        return false;
    }

    err = icicle_mem_map(icicle, startAddr, newSize, perms);
    if (err != 0){
        LOG_ERROR("Unable to remap the memory region which was unmapped with a bigger size!");
        LOG_NOTICE("Attempting to recover the unmapped memory region...");
        err = icicle_vm_restore(ic, tempMemSnapshot);
        if (err != 0)
        {
            LOG_ERROR("Unable to recover the unmapped memory region!");
        }

        LOG_INFO("The memory maps are now in the default state.");
        icicle_vm_snapshot_free(tempMemSnapshot);
        return true;
    }

    // we have to touch the avoid fragmentation bug
    size_t outSize{};
    icicle_mem_read(icicle, startAddr, newSize, &outSize);

    std::cout << "After the remapping" << std::endl;
    return true;
}


static int lastMemInfoSize;
bool keep = false;
void memoryMapWindow()
{
    auto memInfo = getMemoryMapping(icicle);
    auto [x, y] = ImGui::GetWindowSize();
    ImGui::SetNextWindowSize({x - 230, (y - 125 + (52 * memInfo.size()))});

    if (ImGui::Begin("Memory Mappings"))
    {
        bool tableSizeInc = false;
        bool tableUpdated = false;
        bool mapped = true;
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
        if (ImGui::BeginTable("memoryMapTable", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Start", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("End", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Permissions", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            std::string startAddrStr{};
            std::string endAddrStr;
            uint64_t newEndAddr{};

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);

            bool noAccess;
            bool read;
            bool write;
            bool execute;
            bool permsChanged = false;
            bool mappingChanged = true;
            bool endAddrChanged = false;

            float posX{};
            float posY{};

            if (lastMemInfoSize > 0 && (lastMemInfoSize != memInfo.size()))
            {
                tableUpdated = true;
                if (lastMemInfoSize < memInfo.size())
                {
                    tableSizeInc = true;
                }
            }

            lastMemInfoSize = memInfo.size();
            const auto inputValue = static_cast<char*>(malloc(80));

            for (int i = 0; i < memInfo.size(); i++)
            {
                ImGui::PushID((i + 1) * 91);
                
                // Convert MemoryProtection enum to individual permission flags
                switch (memInfo[i].protection) {
                    case NoAccess:
                        read = false;
                        write = false;
                        execute = false;
                        break;
                    case ReadOnly:
                        read = true;
                        write = false;
                        execute = false;
                        break;
                    case ReadWrite:
                        read = true;
                        write = true;
                        execute = false;
                        break;
                    case ExecuteOnly:
                        read = false;
                        write = false;
                        execute = true;
                        break;
                    case ExecuteRead:
                        read = true;
                        write = false;
                        execute = true;
                        break;
                    case ExecuteReadWrite:
                        read = true;
                        write = true;
                        execute = true;
                        break;
                    default:
                        read = false;
                        write = false;
                        execute = false;
                        break;
                }

                ImGui::SetNextItemWidth(-FLT_MIN);
                ImGui::TableSetColumnIndex(0);


                ImGui::PushID(("first" + std::to_string(i + 1)).c_str());
                posY = ImGui::GetCursorPosY();
                posY += 2.5;

                ImGui::SetCursorPosY(posY);
                ImGui::Text("%d.", i + 1);
                ImGui::PopID();

                ImGui::TableSetColumnIndex(1);

                ImGui::PushID(("second" + std::to_string(i)).c_str());
                ImGui::SetNextItemWidth(150);

                posY = ImGui::GetCursorPosY();
                posX = ImGui::GetCursorPosX();
                posY += 3;
                posX += 2;

                ImGui::SetCursorPosY(posY);
                std::stringstream ss;
                ss << "0x" << std::setfill('0') << std::hex << memInfo[i].address;
                ImGui::PushStyleColor(ImGuiCol_TextLink, ImColor(138, 173, 244).Value);
                if (ImGui::TextLink(ss.str().c_str()))
                {
                    memoryEditorWindow.OptShowAddWindowButton = false;
                    newMemEditWindowsInfo memWindowInfo = {memoryEditorWindow, memInfo[i].address, memInfo[i].size};
                    newMemEditWindows.push_back(memWindowInfo);
                }
                ImGui::PopStyleColor();
                ss.clear();
                ss.str("");
                ImGui::PopID();
                ImGui::TableSetColumnIndex(2);
                ImGui::PushID(("third" + std::to_string(i)).c_str());
                ImGui::SetNextItemWidth(150);
                uint64_t endAddr = memInfo[i].size + memInfo[i].address;
                strncpy(inputValue, std::to_string(endAddr).c_str(), std::to_string(endAddr).length());
                if (InputHexadecimal("##end_addr", inputValue, ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue))
                {
                    newEndAddr = strtoll(inputValue, nullptr, 16);
                    if (newEndAddr != endAddr || newEndAddr != (endAddr + 1))
                    {
                        endAddrChanged = true;
                    }
                }

                ImGui::PopID();
                ImGui::PushStyleColor(ImGuiCol_CheckMark, ImColor(140, 170, 238).Value);
                ImGui::TableSetColumnIndex(3);
                ImGui::PushID(("fourth" + std::to_string(i)).c_str());

                posX = ImGui::GetCursorPosX() + 2;

                ImGui::SetCursorPosX(posX);
                ImGui::Selectable("Read: ");
                ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);
                ImGui::SameLine();
                ImGui::PushID((i + 5) * 3);
                posX = ImGui::GetCursorPosX();
                posX += 6;
                ImGui::SetCursorPosX(posX);
                ImGui::Checkbox("##check_read", &read);

                if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
                {
                    read = !read;
                    permsChanged = true;
                }

                ImGui::SameLine();
                ImGui::Dummy({2, 2});
                ImGui::SameLine();
                ImGui::PopID();
                ImGui::SameLine();
                ImGui::Selectable("Write: ");
                ImGui::SameLine();
                ImGui::PushID((i + 1) * 3);
                ImGui::Checkbox(("###Check2_" + std::to_string(i * 2)).c_str(), &write);

                if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
                {
                    write = !write;
                    permsChanged = true;
                }
                ImGui::GetStyle();
                ImGui::PopID();
                ImGui::SameLine();
                ImGui::Dummy({2, 2});
                ImGui::SameLine();
                ImGui::SameLine();
                ImGui::Selectable("Execute: ");
                ImGui::SameLine();
                ImGui::PushID((i + 1) * 5);

                ImGui::Checkbox("###Check3_", &execute);
                if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
                {
                    execute = !execute;
                    permsChanged = true;
                }

                ImGui::PopID();

                posX = ImGui::GetCursorPosX() + 2;

                ImGui::SetCursorPosX(posX);
                ImGui::Selectable("Mapped: ");
                ImGui::SameLine();

                ImGui::Checkbox("###Check4_", &mapped);
                if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
                {
                    bool unmap = tinyfd_messageBox("Confirmation required!", "Are you sure you want to unmap it?", "okcancel", "error", 0);

                    if (unmap)
                    {
                        icicle_mem_unmap(icicle, memInfo[i].address, memInfo[i].size);
                    }
                }

                ImGui::PopFont ();
                ImGui::TableNextRow();
                ImGui::PopID();
                ImGui::PopStyleColor();
                ImGui::PopID();

                if (permsChanged)
                {
                    // Convert individual flags back to MemoryProtection enum
                    MemoryProtection newPerms;
                    if (read && write && execute) {
                        newPerms = ExecuteReadWrite;
                    } else if (read && execute) {
                        newPerms = ExecuteRead;
                    } else if (execute) {
                        newPerms = ExecuteOnly;
                    } else if (read && write) {
                        newPerms = ReadWrite;
                    } else if (read) {
                        newPerms = ReadOnly;
                    } else {
                        newPerms = NoAccess;
                    }
                    
                    updateMemoryPermissions(icicle, memInfo[i].address, memInfo[i].address + memInfo[i].size, newPerms);
                    permsChanged = false;
                }

                if (endAddrChanged)
                {
                    if (expandMemoryRegion(icicle, memInfo[i].address, memInfo[i].size + memInfo[i].address,
                                           newEndAddr,
                                           memInfo[i].size, memInfo[i].protection))
                    endAddrChanged = false;
                }
            }

            ImGui::PopFont();
            free(inputValue);
            ImGui::EndTable();
        }

        if (tableUpdated)
        {
            auto [x, y] = ImGui::GetWindowSize();
            if (tableSizeInc)
            {
                ImGui::SetNextWindowSize({x, y + 25});
            }
            else
            {
                ImGui::SetNextWindowSize({x, y - 25});
            }
        }

        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
        if (ImGui::Button("ADD"))
        {
            keep = true;
        }


        ImGui::SameLine();
        auto [x, y] = ImGui::GetWindowSize();
        const ImVec2 windowSize = ImGui::GetWindowSize();
        const ImVec2 padding = ImGui::GetStyle().WindowPadding;

        ImVec2 contentRegion = ImGui::GetContentRegionAvail();

        const ImVec2 widgetSize = ImGui::CalcTextSize("Add");
        ImGui::SetCursorPos(ImVec2(windowSize.x - padding.x - widgetSize.x,
                                   windowSize.y - padding.y - widgetSize.y + 16 - ImGui::GetFrameHeight()));
        if (ImGui::Button("OK"))
        {
            memoryMapsUI = false;
        }
        ImGui::PopFont();
    }

    if (keep)
    {
        auto [address, size] = infoPopup("Map a new region", "Multiple of 4KB");
        if (address != 0 && size != 0)
        {
            auto err = icicle_mem_map(icicle, address, size, MemoryProtection::NoAccess);
            if (err != 0)
            {
                LOG_INFO("Unable to map the newly requested memory region.");
                keep = false;
            }
            else
            {
                keep =  false;
            }
        }
        if (address == 0 && size == 1)
        {
            keep = false;
        }
    }
    ImGui::End();
    ImGui::CloseCurrentPopup();
}
