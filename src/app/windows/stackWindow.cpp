#include "windows.hpp"

void stackEditorWindow(){
    auto io = ImGui::GetIO();
    static MemoryEditor mem_edit_2;
    mem_edit_2.OptShowAscii = false;
    mem_edit_2.Cols = 8;

    ImGui::PushFont(io.Fonts->Fonts[3]);
//  replace with stack stuff
    static char data[5 * 1024 * 1024];
    size_t data_size = 0x10000;
//    char *test = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce tortor urna, eleifend vel arcu vel, semper ultrices nisl. Aenean enim augue, dignissim at tempus vulputate, laoreet eget urna. Etiam aliquam, nibh non volutpat ultricies, massa tellus rutrum lectus, ut pellentesque purus enim vitae lorem. Vivamus cursus consequat turpis, sed convallis urna pretium at. Mauris fringilla lacus mi, ut gravida justo auctor vel. Nulla consectetur laoreet pharetra. Vivamus dui lectus, lobortis id ultricies vitae, viverra ut lacus. Fusce rutrum, erat consequat fringilla porttitor, mi elit sodales erat, a tempus turpis erat vel leo. Aenean ullamcorper blandit felis in sodales. Nunc sed massa sed erat luctus viverra. Suspendisse sem massa, pharetra pulvinar massa eu, rutrum vestibulum dui. Mauris sed posuere tellus. Curabitur ac placerat nunc, at pellentesque erat. Nam quis ligula pellentesque, rhoncus velit sed, pharetra leo. Ut tempor tincidunt orci, in scelerisque arcu tincidunt a. Sed eget sem et ligula finibus facilisis. Nunc vulputate mollis nulla, non ultrices libero faucibus non. Duis erat leo, pretium in tincidunt vel, placerat at nisl. Etiam elit velit, rutrum et sapien eget, efficitur egestas odio. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Sed viverra blandit ex at ultrices. Suspendisse potenti. Donec luctus metus sit amet augue elementum pellentesque. Sed rhoncus tincidunt arcu, nec congue mauris porta eget. Praesent id tellus neque. Mauris ultricies augue quis ante dapibus, eget lacinia nisi elementum. Fusce ornare condimentum mattis. Pellentesque ut congue mauris. Nullam et orci iaculis, malesuada lacus in, placerat nunc.";
//    memcpy(STACK_ADDRESS, test, data_size);
    uc_mem_read(uc, STACK_ADDRESS, data, data_size);
    mem_edit_2.DrawWindow("Stack", (void*)data, STACK_SIZE);
    ImGui::PopFont();
}
