#ifndef SPOT_PATCHING_H
#define SPOT_PATCHING_H

#include <vector>

struct PatchWindow {
    int row;
    int col;
    int height;
    int width;
};

std::vector<PatchWindow> compute_patch_plan(
    int H,
    int W,
    int FH,
    int FW,
    int stride,
    int overlap,
    int patch_h,
    int patch_w);

#endif