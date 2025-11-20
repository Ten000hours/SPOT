#include "SPOT/patching.h"

std::vector<PatchWindow> compute_patch_plan(
    int H,
    int W,
    int FH,
    int FW,
    int stride,
    int overlap,
    int patch_h,
    int patch_w)
{
    std::vector<PatchWindow> plan;
    if (H <= 0 || W <= 0 || FH <= 0 || FW <= 0 || stride <= 0 || patch_h <= 0 || patch_w <= 0) return plan;
    int step_h = patch_h - overlap;
    int step_w = patch_w - overlap;
    if (step_h <= 0) step_h = 1;
    if (step_w <= 0) step_w = 1;
    for (int r = 0; r < H; r += step_h) {
        int h_end = r + patch_h;
        if (h_end > H) h_end = H;
        int h = h_end - r;
        if (h <= 0) break;
        for (int c = 0; c < W; c += step_w) {
            int w_end = c + patch_w;
            if (w_end > W) w_end = W;
            int w = w_end - c;
            if (w <= 0) break;
            plan.push_back({r, c, h, w});
            if (w_end >= W && h_end >= H) break;
        }
        if (h_end >= H) break;
    }
    return plan;
}