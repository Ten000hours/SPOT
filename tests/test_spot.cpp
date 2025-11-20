#define SCI_HE
#define BITLEN_41

#include "globals.h"
#include "LinearHE/conv-field.h"
#include "SPOT/patching.h"

using namespace std;
using namespace sci;
using namespace seal;

int port = 32001;
string address;
bool localhost = true;

int image_h = 56;
int inp_chans = 64;
int filter_h = 3;
int out_chans = 64;
int stride = 1;
int pad_l = 1;
int pad_r = 1;
int patch_h = 16;
int patch_w = 16;
int overlap = 2;
int filter_precision = 12;

int main(int argc, char** argv) {
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = server = 1; BOB = client = 2");
    amap.arg("p", port, "Port Number");
    amap.arg("h", image_h, "Image Height/Width");
    amap.arg("f", filter_h, "Filter Height/Width");
    amap.arg("i", inp_chans, "Input Channels");
    amap.arg("o", out_chans, "Ouput Channels");
    amap.arg("s", stride, "stride");
    amap.arg("pl", pad_l, "Left Padding");
    amap.arg("pr", pad_r, "Right Padding");
    amap.arg("ph", patch_h, "Patch Height");
    amap.arg("pw", patch_w, "Patch Width");
    amap.arg("ov", overlap, "Overlap");
    amap.arg("fp", filter_precision, "Filter Precision");
    amap.arg("lo", localhost, "Localhost Run?");
    amap.parse(argc, argv);

    if(not localhost) {
        address = "127.0.0.1";
    } else {
        address = "127.0.0.1";
    }

    io = new NetIO(party==1 ? nullptr:address.c_str(), port);

    ConvField he_conv(party, io);

    int newH = 1 + (image_h+pad_l+pad_r-filter_h)/stride;
    int N = 1;
    int W = image_h;
    int FW = filter_h;
    int zPadWLeft = pad_l;
    int zPadWRight = pad_r;
    int strideW = stride;
    int newW = newH;

    vector<vector<vector<vector<uint64_t>>>> inputArr(N);
    vector<vector<vector<vector<uint64_t>>>> filterArr(filter_h);
    vector<vector<vector<vector<uint64_t>>>> outArr(N);

    PRG128 prg;
    for(int i = 0; i < N; i++){
        outArr[i].resize(newH);
        for(int j = 0; j < newH; j++) {
            outArr[i][j].resize(newW);
            for(int k = 0; k < newW; k++) {
                outArr[i][j][k].resize(out_chans);
            }
        }
    }
    // Allocate filter shapes on both parties; only server fills values
    for(int i = 0; i < filter_h; i++){
        filterArr[i].resize(FW);
        for(int j = 0; j < FW; j++) {
            filterArr[i][j].resize(inp_chans);
            for(int k = 0; k < inp_chans; k++) {
                filterArr[i][j][k].resize(out_chans);
                if(party == SERVER) {
                    prg.random_data(filterArr[i][j][k].data(), out_chans*sizeof(uint64_t));
                    for(int h = 0; h < out_chans; h++) {
                        filterArr[i][j][k][h] = ((int64_t) filterArr[i][j][k][h]) >> (64 - filter_precision);
                    }
                } else {
                    for(int h = 0; h < out_chans; h++) filterArr[i][j][k][h] = 0;
                }
            }
        }
    }
    for(int i = 0; i < N; i++){
        inputArr[i].resize(image_h);
        for(int j = 0; j < image_h; j++) {
            inputArr[i][j].resize(W);
            for(int k = 0; k < W; k++) {
                inputArr[i][j][k].resize(inp_chans);
                prg.random_mod_p<uint64_t>(inputArr[i][j][k].data(), inp_chans, prime_mod);
            }
        }
    }

    auto plan = compute_patch_plan(image_h, image_h, filter_h, filter_h, stride, overlap, patch_h, patch_w);

    INIT_TIMER;
    START_TIMER;
    for (auto &win : plan) {
        vector<vector<vector<vector<uint64_t>>>> patchInput(N);
        patchInput[0].resize(win.height);
        for(int r = 0; r < win.height; r++){
            patchInput[0][r].resize(win.width);
            for(int c = 0; c < win.width; c++){
                patchInput[0][r][c].resize(inp_chans);
                for(int ch = 0; ch < inp_chans; ch++){
                    patchInput[0][r][c][ch] = inputArr[0][win.row + r][win.col + c][ch];
                }
            }
        }
        int newH_patch = 1 + (win.height + pad_l + pad_r - filter_h) / stride;
        int newW_patch = newH_patch;
        vector<vector<vector<vector<uint64_t>>>> patchOut(N);
        patchOut[0].resize(newH_patch);
        for(int j = 0; j < newH_patch; j++) {
            patchOut[0][j].resize(newW_patch);
            for(int k = 0; k < newW_patch; k++) {
                patchOut[0][j][k].resize(out_chans);
            }
        }
        he_conv.convolution(N, win.height, win.width, inp_chans, filter_h, filter_h, out_chans,
                            pad_l, pad_r, pad_l, pad_r, stride, stride,
                            patchInput, filterArr, patchOut, false, true);
    }
    STOP_TIMER("SPOT Pipeline Time");

    io->flush();
    return 0;
}