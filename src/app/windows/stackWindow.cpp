#include "windows.hpp"

void stackEditorWindow(){
    auto io = ImGui::GetIO();
    static MemoryEditor stackEditor;
    stackEditor.OptShowAscii = false;
    stackEditor.Cols = 4;

    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[5 * 1024 * 1024];

    //  pop does not remove the popped element from the stack, it only copies it
    uc_mem_read(uc, STACK_ADDRESS, data, STACK_SIZE);
    stackEditor.DrawWindow("Stack", (void*)data, STACK_SIZE);
    ImGui::PopFont();
}
