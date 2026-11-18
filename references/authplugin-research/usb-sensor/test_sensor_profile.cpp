#include "SensorProfile.h"
#include <cassert>
#include <vector>

using Bytes = std::vector<uint8_t>;

static void sizeConfig(Bytes &bytes) {
    bytes[2] = static_cast<uint8_t>(bytes.size());
    bytes[3] = static_cast<uint8_t>(bytes.size() >> 8);
}

static bool accepts(const Bytes &d) { return elan::hasSensorInterface(d.data(), d.size()); }

int main() {
    Bytes config{9, 2, 0, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 255, 0, 0, 0,
                 7, 5, 1, 2, 64, 0, 0, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x83, 2, 64, 0, 0};
    sizeConfig(config);
    assert(accepts(config));
    for (size_t n = 0; n < config.size(); ++n) assert(!elan::hasSensorInterface(config.data(), n));
    for (auto correction : std::vector<std::pair<size_t, uint8_t>>{
        {0, 1}, {1, 1}, {2, 5}, {5, 2}, {11, 1}, {12, 1}, {13, 2}, {14, 14}, {15, 3}, {16, 2},
        {18, 0}, {18, 6}, {20, 0x81}, {21, 3}, {22, 0}, {27, 1}, {34, 0x82}}) {
        auto bad = config;
        bad[correction.first] = correction.second;
        assert(!accepts(bad));
    }
    Bytes other{9, 4, 1, 0, 1, 255, 0, 0, 0, 7, 5, 0x83, 2, 64, 0, 0};
    Bytes split(config.begin(), config.end() - 7);
    split[13] = 2;
    split.insert(split.end(), other.begin(), other.end());
    sizeConfig(split);
    assert(!accepts(split));
    auto extra = config;
    extra.insert(extra.end(), other.begin(), other.end());
    sizeConfig(extra);
    assert(accepts(extra));
    extra[config.size() + 2] = 0;
    assert(!accepts(extra));
}
