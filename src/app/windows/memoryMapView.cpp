#include "windows.hpp"

// std::vector<memoryMapInfo> getMemoryMapping(uc_engine* uc)
// {
//     uc_mem_region* regionsInformation;
//     uint32_t count;
//     uc_mem_regions(uc, &regionsInformation, &count);
//
//     std::vector<memoryMapInfo> memMapInfo;
//     memMapInfo.reserve(count);
//     const uc_mem_region* regionInfo = regionsInformation;
//
//     for (int i = 0; i < count; i++)
//     {
//         memMapInfo.push_back({regionInfo->begin, regionInfo->end, regionInfo->perms});
//         regionInfo++;
//     }
//
//     uc_free(regionsInformation);
//     return memMapInfo;
// }
//
// inline bool updateMemoryPermissions(uc_engine* uc, const uint64_t startAddr, const uint64_t endAddr,
//                                     const uint32_t newPerms)
// {
//     auto err = uc_mem_protect(uc, startAddr, (endAddr - startAddr) + 1, newPerms);
//     if (err != UC_ERR_OK)
//     {
//         return false;
//     }
//
//     return true;
// }

// bool expandMemoryRegion(uc_engine* uc, const uint64_t startAddr, uint64_t oldEndAddr, uint64_t newEndAddr,
//                         const uint64_t oldSize, const uint32_t perms)
// {
//     if (!(perms & UC_PROT_READ && perms & UC_PROT_WRITE))
//     {
//         LOG_ERROR("The memory region expansion process could not be completed because the memory region does not have read and write permissions.");
//         return false;
//     }
//
//     if (startAddr > newEndAddr)
//     {
//         return false;
//     }
//
//     auto newSize = (newEndAddr - startAddr);
//
//     if (((newSize % 4096) != 0))
//     {
//         LOG_ALERT("The new size requested for the memory region is not a multiple of 4096, rounding up...");
//         tinyfd_messageBox(
//             "Warning",
//             "The new end address provided by you is not a multiple of the page size. The number will be rounded up to a multiple of 4KB.",
//             "ok", "warning", 1);
//         newEndAddr = (newEndAddr + 4095) & ~4095;
//         newSize = newEndAddr - startAddr;
//         LOG_INFO("Rounded up size is " << newSize);
//     }
//
//     uc_err ucErr{};
//
//     // maybe allocate a page?
//     const auto saved = static_cast<char*>(malloc(oldSize));
//
//     ucErr = uc_mem_read(uc, startAddr, saved, oldSize);
//     if (ucErr != UC_ERR_OK && ucErr != UC_ERR_READ_PROT)
//     {
//         LOG_ERROR("Unable to read from the memory region for expansion.");
//         return false;
//     }
//
//     ucErr = uc_mem_unmap(uc, startAddr, oldSize);
//     if (ucErr != UC_ERR_OK)
//     {
//         LOG_ERROR("Unable to unmap the memory region for expansion.");
//         return false;
//     }
//
//     ucErr = uc_mem_map(uc, startAddr, newSize, perms);
//     if (ucErr != UC_ERR_OK)
//     {
//         LOG_ERROR("Unable to remap the memory region which was unmapped with a bigger size!");
//         LOG_NOTICE("Attempting to recover the unmapped memory region...");
//
//         ucErr = uc_mem_map(uc, startAddr, oldSize, perms);
//
//         if (ucErr != UC_ERR_OK)
//         {
//             LOG_INFO("Mapping error during recovery!");
//             LOG_ERROR("Memory map recovery failed. Memory map in inrecoverable state.");
//             return false;
//         }
//         else
//         {
//             LOG_INFO("Recovery mapping sucessful! Proceeding...");
//             ucErr = uc_mem_write(uc, startAddr, saved, sizeof(saved));
//             // UC_ERR_WRITE_PROT is not likely or is unreachable.
//             if (ucErr != UC_ERR_OK && ucErr != UC_ERR_WRITE_PROT)
//             {
//                 LOG_INFO("Memory writing error during recovery!");
//                 LOG_ERROR("Memory map recovery failed. Memory map in inrecoverable state.");
//                 return false;
//             }
//
//             LOG_INFO("Recovery write sucessful! Proceeding...");
//             LOG_INFO("The memory maps are now in the default state.");
//             return true;
//         }
//
//         return false;
//     }
//
//     ucErr = uc_mem_write(uc, startAddr, saved, sizeof(saved));
//     if (ucErr != UC_ERR_OK)
//     {
//         LOG_ERROR("Unable to write to the memory region which was unmapped with a bigger size!");
//         return false;
//     }
//
//     free(saved);
//     return true;
// }
//
// static int lastMemInfoSize;
// bool keep = false;
// void memoryMapWindow()
// {
//     auto memInfo = getMemoryMapping(uc);
//     auto [x, y] = ImGui::GetWindowSize();
//     ImGui::SetNextWindowSize({x - 230, (y - 125 + (52 * memInfo.size()))});
//
//     if (ImGui::Begin("Memory Mappings"))
//     {
//         bool tableSizeInc = false;
//         bool tableUpdated = false;
//         bool mapped = true;
//         ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
//         if (ImGui::BeginTable("memoryMapTable", 4,
//                               ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
//         {
//             ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthStretch);
//             ImGui::TableSetupColumn("Start", ImGuiTableColumnFlags_WidthStretch);
//             ImGui::TableSetupColumn("End", ImGuiTableColumnFlags_WidthStretch);
//             ImGui::TableSetupColumn("Permissions", ImGuiTableColumnFlags_WidthStretch);
//             ImGui::TableHeadersRow();
//
//             std::string startAddrStr{};
//             std::string endAddrStr;
//             uint64_t newEndAddr{};
//
//             ImGui::TableNextRow();
//             ImGui::TableSetColumnIndex(0);
//
//             bool read;
//             bool write;
//             bool execute;
//             bool permsChanged = false;
//             bool mappingChanged = true;
//             bool endAddrChanged = false;
//
//             float posX{};
//             float posY{};
//
//             if (lastMemInfoSize > 0 && (lastMemInfoSize != memInfo.size()))
//             {
//                 tableUpdated = true;
//                 if (lastMemInfoSize < memInfo.size())
//                 {
//                     tableSizeInc = true;
//                 }
//             }
//
//             lastMemInfoSize = memInfo.size();
//             const auto inputValue = static_cast<char*>(malloc(80));
//
//             for (int i = 0; i < memInfo.size(); i++)
//             {
//                 ImGui::PushID((i + 1) * 91);
//                 read = memInfo[i].perms & UC_PROT_READ;
//                 write = memInfo[i].perms & UC_PROT_WRITE;
//                 execute = memInfo[i].perms & UC_PROT_EXEC;
//
//                 ImGui::SetNextItemWidth(-FLT_MIN);
//                 ImGui::TableSetColumnIndex(0);
//
//
//                 ImGui::PushID(("first" + std::to_string(i + 1)).c_str());
//                 posY = ImGui::GetCursorPosY();
//                 posY += 2.5;
//
//                 ImGui::SetCursorPosY(posY);
//                 ImGui::Text("%d.", i + 1);
//                 ImGui::PopID();
//
//                 ImGui::TableSetColumnIndex(1);
//
//                 ImGui::PushID(("second" + std::to_string(i)).c_str());
//                 ImGui::SetNextItemWidth(150);
//
//                 posY = ImGui::GetCursorPosY();
//                 posX = ImGui::GetCursorPosX();
//                 posY += 3;
//                 posX += 2;
//
//                 ImGui::SetCursorPosY(posY);
//                 std::stringstream ss;
//                 ss << "0x" << std::setfill('0') << std::hex << memInfo[i].start;
//                 ImGui::PushStyleColor(ImGuiCol_TextLink, ImColor(138, 173, 244).Value);
//                 if (ImGui::TextLink(ss.str().c_str()))
//                 {
//                     memoryEditorWindow.OptShowAddWindowButton = false;
//                     newMemEditWindowsInfo memWindowInfo = {memoryEditorWindow, memInfo[i].start, memInfo[i].end - memInfo[i].start + 1};
//                     newMemEditWindows.push_back(memWindowInfo);
//                 }
//                 ImGui::PopStyleColor();
//                 ss.clear();
//                 ss.str("");
//                 ImGui::PopID();
//                 ImGui::TableSetColumnIndex(2);
//                 ImGui::PushID(("third" + std::to_string(i)).c_str());
//                 ImGui::SetNextItemWidth(150);
//
//                 strncpy(inputValue, std::to_string(memInfo[i].end + 1).c_str(), std::to_string(memInfo[i].end + 1).length());
//                 if (InputHexadecimal("##end_addr", inputValue, ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue))
//                 {
//                     newEndAddr = strtol(inputValue, nullptr, 16);
//                     if (newEndAddr != memInfo[i].end || newEndAddr != (memInfo[i].end + 1))
//                     {
//                         endAddrChanged = true;
//                     }
//                 }
//
//                 ImGui::PopID();
//                 ImGui::PushStyleColor(ImGuiCol_CheckMark, ImColor(140, 170, 238).Value);
//                 ImGui::TableSetColumnIndex(3);
//                 ImGui::PushID(("fourth" + std::to_string(i)).c_str());
//
//                 posX = ImGui::GetCursorPosX() + 2;
//
//                 ImGui::SetCursorPosX(posX);
//                 ImGui::Selectable("Read: ");
//                 ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);
//                 ImGui::SameLine();
//                 ImGui::PushID((i + 5) * 3);
//                 posX = ImGui::GetCursorPosX();
//                 posX += 6;
//                 ImGui::SetCursorPosX(posX);
//                 ImGui::Checkbox("##check_read", &read);
//
//                 if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
//                 {
//                     read = !read;
//                     permsChanged = true;
//                 }
//
//                 ImGui::SameLine();
//                 ImGui::Dummy({2, 2});
//                 ImGui::SameLine();
//                 ImGui::PopID();
//                 ImGui::SameLine();
//                 ImGui::Selectable("Write: ");
//                 ImGui::SameLine();
//                 ImGui::PushID((i + 1) * 3);
//                 ImGui::Checkbox(("###Check2_" + std::to_string(i * 2)).c_str(), &write);
//
//                 if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
//                 {
//                     write = !write;
//                     permsChanged = true;
//                 }
//                 ImGui::GetStyle();
//                 ImGui::PopID();
//                 ImGui::SameLine();
//                 ImGui::Dummy({2, 2});
//                 ImGui::SameLine();
//                 ImGui::SameLine();
//                 ImGui::Selectable("Execute: ");
//                 ImGui::SameLine();
//                 ImGui::PushID((i + 1) * 5);
//
//                 ImGui::Checkbox("###Check3_", &execute);
//                 if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
//                 {
//                     execute = !execute;
//                     permsChanged = true;
//                 }
//
//                 ImGui::PopID();
//
//                 posX = ImGui::GetCursorPosX() + 2;
//
//                 ImGui::SetCursorPosX(posX);
//                 ImGui::Selectable("Mapped: ");
//                 ImGui::SameLine();
//
//                 ImGui::Checkbox("###Check4_", &mapped);
//                 if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(0))
//                 {
//                     bool unmap = tinyfd_messageBox("Confirmation required!", "Are you sure you want to unmap it?", "okcancel", "error", 0);
//
//                     if (unmap)
//                     {
//                         uc_mem_unmap(uc, memInfo[i].start, memInfo[i].end - memInfo[i].start + 1);
//                     }
//                 }
//
//                 ImGui::PopFont ();
//                 ImGui::TableNextRow();
//                 ImGui::PopID();
//                 ImGui::PopStyleColor();
//                 ImGui::PopID();
//
//                 if (permsChanged)
//                 {
//                     const uint32_t perms = (read ? UC_PROT_READ : UC_PROT_NONE) | (write ? UC_PROT_WRITE : UC_PROT_NONE)
//                         | (execute ? UC_PROT_EXEC : UC_PROT_NONE);
//                     updateMemoryPermissions(uc, memInfo[i].start, memInfo[i].end, perms);
//                     permsChanged = false;
//                 }
//
//                 if (endAddrChanged)
//                 {
//                     if (expandMemoryRegion(uc, memInfo[i].start, memInfo[i].end,
//                                            strtoll(std::to_string(newEndAddr).c_str(), nullptr, 16),
//                                            (memInfo[i].end - memInfo[i].start) + 1, memInfo[i].perms))
//                     {
//                         memInfo[i].end = newEndAddr;
//                     }
//                     endAddrChanged = false;
//                 }
//             }
//
//             ImGui::PopFont();
//             free(inputValue);
//             ImGui::EndTable();
//         }
//
//         if (tableUpdated)
//         {
//             auto [x, y] = ImGui::GetWindowSize();
//             if (tableSizeInc)
//             {
//                 ImGui::SetNextWindowSize({x, y + 25});
//             }
//             else
//             {
//                 ImGui::SetNextWindowSize({x, y - 25});
//             }
//         }
//
//         ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
//         if (ImGui::Button("ADD"))
//         {
//             keep = true;
//         }
//
//
//         ImGui::SameLine();
//         auto [x, y] = ImGui::GetWindowSize();
//         const ImVec2 windowSize = ImGui::GetWindowSize();
//         const ImVec2 padding = ImGui::GetStyle().WindowPadding;
//
//         ImVec2 contentRegion = ImGui::GetContentRegionAvail();
//
//         const ImVec2 widgetSize = ImGui::CalcTextSize("Add");
//         ImGui::SetCursorPos(ImVec2(windowSize.x - padding.x - widgetSize.x,
//                                    windowSize.y - padding.y - widgetSize.y + 16 - ImGui::GetFrameHeight()));
//         if (ImGui::Button("OK"))
//         {
//             memoryMapsUI = false;
//         }
//         ImGui::PopFont();
//     }
//
//     if (keep)
//     {
//         auto [address, size] = infoPopup("Map a new region", "Multiple of 4KB");
//         if (address != 0 && size != 0)
//         {
//             uc_err ucErr = uc_mem_map(uc, address, size, UC_PROT_NONE);
//             if (ucErr != UC_ERR_OK)
//             {
//                 LOG_INFO("Unable to map the newly requested memory region.");
//                 keep = false;
//             }
//             else
//             {
//                 keep =  false;
//             }
//         }
//         if (address == 0 && size == 1)
//         {
//             keep = false;
//         }
//     }
//     ImGui::End();
//     ImGui::CloseCurrentPopup();
// }
