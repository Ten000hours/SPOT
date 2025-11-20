#include <iostream>
#include "SPOT/patching.h"

int main() {
    int H = 56;
    int W = 56;
    int FH = 3;
    int FW = 3;
    int stride = 1;
    int overlap = 2;
    int patch_h = 16;
    int patch_w = 16;
    auto plan = compute_patch_plan(H, W, FH, FW, stride, overlap, patch_h, patch_w);
    std::cout << "patch_count=" << plan.size() << std::endl;
    if (!plan.empty()) {
        std::cout << plan[0].row << "," << plan[0].col << "," << plan[0].height << "," << plan[0].width << std::endl;
    }
    return 0;
}