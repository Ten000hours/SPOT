#define SCI_HE
#define BITLEN_41

#include "globals.h"
#include "LinearHE/conv-field.h"
#include "NonLinear/relu-field.h"
#include "OT/ot_pack.h"
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include "SPOT/patching.h"

using namespace std;
using namespace sci;
using namespace seal;

int port = 32002;
string address;
bool localhost = true;

int image_h = 8;
int inp_chans = 4;
int filter_h = 3;
int out_chans = 4;
int stride = 1;
int pad_l = 1;
int pad_r = 1;
int patch_h = 4;
int patch_w = 4;
int overlap = 2;
int filter_precision = 12;
int threads = 2;
int num_patches = 10;

void run_relu(NetIO* io_ot, OTPack<NetIO>* otpack_local, uint64_t* z, uint64_t* x, int lnum_relu) {
    ReLUFieldProtocol<NetIO, uint64_t>* relu_oracle;
    relu_oracle = new ReLUFieldProtocol<NetIO, uint64_t>(party, FIELD, io_ot, 41, 4, prime_mod, otpack_local);
    relu_oracle->relu_pregen(z, x, lnum_relu);
    delete relu_oracle;
}

int main(int argc, char** argv) {
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = server = 1; BOB = client = 2");
    amap.arg("p", port, "Port Number");
    amap.arg("ph", patch_h, "Patch Height");
    amap.arg("pw", patch_w, "Patch Width");
    amap.arg("ov", overlap, "Overlap");
    amap.arg("t", threads, "Parallel ReLU threads");
    amap.arg("np", num_patches, "Num patches to process");
    amap.arg("h", image_h, "Image Height/Width");
    amap.arg("lo", localhost, "Localhost Run?");
    amap.parse(argc, argv);

    address = "127.0.0.1";
    io = new NetIO(party==1 ? nullptr:address.c_str(), port);
    auto plan = compute_patch_plan(image_h, image_h, filter_h, filter_h, stride, overlap, patch_h, patch_w);
    int P = plan.size();
    if (num_patches < P) plan = std::vector<PatchWindow>(plan.begin(), plan.begin()+num_patches);
    P = plan.size();
    std::vector<NetIO*> io_ot_patch(P);
    std::vector<OTPack<NetIO>*> otpack_patch(P);
    std::vector<NetIO*> io_he_patch(P);
    std::vector<ConvField*> he_patch(P);
    for (int i = 0; i < P; i++) {
        io_ot_patch[i] = new NetIO(party==1 ? nullptr:address.c_str(), port+1+i);
        if (i == 0) otpack_patch[i] = new OTPack<NetIO>(io_ot_patch[i], party, 4, 41);
        else {
            otpack_patch[i] = new OTPack<NetIO>(io_ot_patch[i], party, 4, 41, false);
            otpack_patch[i]->copy(otpack_patch[0]);
        }
        io_he_patch[i] = new NetIO(party==1 ? nullptr:address.c_str(), port+50+i);
        he_patch[i] = new ConvField(party, io_he_patch[i]);
    }

    

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
        inputArr[i].resize(image_h);
        for(int j = 0; j < image_h; j++) {
            inputArr[i][j].resize(W);
            for(int k = 0; k < W; k++) {
                inputArr[i][j][k].resize(inp_chans);
                prg.random_mod_p<uint64_t>(inputArr[i][j][k].data(), inp_chans, prime_mod);
            }
        }
    }
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

    auto t0 = std::chrono::high_resolution_clock::now();
    bool spot_first_relu_printed = false;
    long long cumulative_inputs = 0;
    int patch_i = 0;
    std::atomic<bool> start_flag(false);
    std::mutex print_mu;
    std::vector<std::thread> spot_threads;
    for (int i = 0; i < P; i++) {
        auto win = plan[i];
        spot_threads.emplace_back([&, i, win]() {
            while (!start_flag.load()) std::this_thread::yield();
            int newH_patch = 1 + (win.height + pad_l + pad_r - filter_h) / stride;
            int newW_patch = newH_patch;
            int relu_inputs = newH_patch * newW_patch * out_chans;
            vector<vector<vector<vector<uint64_t>>>> patchInput(1);
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
            vector<vector<vector<vector<uint64_t>>>> patchOut(1);
            patchOut[0].resize(newH_patch);
            for(int j = 0; j < newH_patch; j++) { patchOut[0][j].resize(newW_patch); for(int k = 0; k < newW_patch; k++) patchOut[0][j][k].resize(out_chans); }
            he_patch[i]->convolution(1, win.height, win.width, inp_chans, filter_h, filter_h, out_chans,
                                     pad_l, pad_r, pad_l, pad_r, stride, stride,
                                     patchInput, filterArr, patchOut, false, true);
            vector<uint64_t> x(relu_inputs);
            int idx = 0;
            for(int j = 0; j < newH_patch; j++) for(int k = 0; k < newW_patch; k++) for(int oc = 0; oc < out_chans; oc++)
                x[idx++] = patchOut[0][j][k][oc];
            vector<uint64_t> z(relu_inputs);
            if (party == SERVER) { for (int ii = 0; ii < relu_inputs; ii++) z[ii] = (x[ii] >> (bitlength-1)) & 1ULL; } else { for (int ii = 0; ii < relu_inputs; ii++) z[ii] = 0ULL; }
            auto pr_start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
            {
                std::lock_guard<std::mutex> lk(print_mu);
                std::cout << (party==SERVER?"[Server] ":"[Client] ") << "SPOT: patch " << i << " ReLU start " << pr_start_ms << " ms" << std::endl;
            }
            run_relu(io_ot_patch[i], otpack_patch[i], z.data(), x.data(), relu_inputs);
            auto pr_end_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
            {
                std::lock_guard<std::mutex> lk(print_mu);
                cumulative_inputs += relu_inputs;
                std::cout << (party==SERVER?"[Server] ":"[Client] ") << "SPOT: patch " << i << " ReLU end   " << pr_end_ms << " ms, cum_inputs=" << cumulative_inputs << std::endl;
                if (!spot_first_relu_printed) { std::cout << "SPOT: first ReLU started at " << pr_start_ms << " ms" << std::endl; spot_first_relu_printed = true; }
            }
        });
    }
    start_flag.store(true);
    for (auto &th : spot_threads) th.join();
    auto spot_end = std::chrono::high_resolution_clock::now();
    auto spot_total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(spot_end - t0).count();
    std::cout << (party==SERVER?"[Server] ":"[Client] ") << "SPOT: total time for " << P << " patches = " << spot_total_ms << " ms" << std::endl;

    // Baseline: compute all patches in parallel, but defer ReLU until all patch convs are done
    std::vector<std::thread> base_threads;
    std::vector<std::vector<uint64_t>> baseX(P);
    for (int i = 0; i < P; i++) {
        auto win = plan[i];
        base_threads.emplace_back([&, i, win]() {
            int newH_patch = 1 + (win.height + pad_l + pad_r - filter_h) / stride;
            int newW_patch = newH_patch;
            vector<vector<vector<vector<uint64_t>>>> patchInput(1);
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
            vector<vector<vector<vector<uint64_t>>>> patchOut(1);
            patchOut[0].resize(newH_patch);
            for(int j = 0; j < newH_patch; j++) { patchOut[0][j].resize(newW_patch); for(int k = 0; k < newW_patch; k++) patchOut[0][j][k].resize(out_chans); }
            he_patch[i]->convolution(1, win.height, win.width, inp_chans, filter_h, filter_h, out_chans,
                                     pad_l, pad_r, pad_l, pad_r, stride, stride,
                                     patchInput, filterArr, patchOut, false, true);
            baseX[i].reserve(newH_patch * newW_patch * out_chans);
            for(int j = 0; j < newH_patch; j++) for(int k = 0; k < newW_patch; k++) for(int oc = 0; oc < out_chans; oc++)
                baseX[i].push_back(patchOut[0][j][k][oc]);
        });
    }
    for (auto &th : base_threads) th.join();
    auto b_start = std::chrono::high_resolution_clock::now();
    std::cout << (party==SERVER?"[Server] ":"[Client] ") << "Baseline: ReLU started at " << std::chrono::duration_cast<std::chrono::milliseconds>(b_start - t0).count() << " ms" << std::endl;
    std::vector<uint64_t> x_all2; for (int i = 0; i < P; i++) x_all2.insert(x_all2.end(), baseX[i].begin(), baseX[i].end());
    std::vector<uint64_t> z_all2(x_all2.size());
    if (party == SERVER) { for (size_t i = 0; i < x_all2.size(); i++) z_all2[i] = (x_all2[i] >> (bitlength-1)) & 1ULL; } else { for (size_t i = 0; i < x_all2.size(); i++) z_all2[i] = 0ULL; }
    run_relu(io_ot_patch[0], otpack_patch[0], z_all2.data(), x_all2.data(), (int)x_all2.size());
    auto b_end = std::chrono::high_resolution_clock::now();
    std::cout << (party==SERVER?"[Server] ":"[Client] ") << "Baseline: ReLU end at " << std::chrono::duration_cast<std::chrono::milliseconds>(b_end - t0).count() << " ms, total_inputs=" << x_all2.size() << std::endl;
    auto baseline_total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(b_end - t0).count();
    std::cout << (party==SERVER?"[Server] ":"[Client] ") << "Baseline: total time for " << P << " patches = " << baseline_total_ms << " ms" << std::endl;

    io->flush();
    for (int i = 0; i < P; i++) { io_ot_patch[i]->flush(); }
    for (int i = 0; i < P; i++) { delete otpack_patch[i]; }
    for (int i = 0; i < P; i++) { delete io_ot_patch[i]; }
    for (int i = 0; i < P; i++) { delete he_patch[i]; }
    for (int i = 0; i < P; i++) { delete io_he_patch[i]; }
    return 0;
}