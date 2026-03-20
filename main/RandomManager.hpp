#pragma once

#include <cstdint>
#include <cstddef>

namespace Rawlen {
namespace Random {

__forceinline constexpr uint64_t rl(uint64_t v, int k) {
    return (v << k) | (v >> (64 - k));
}

__forceinline constexpr uint64_t rr(uint64_t v, int k) {
    return (v >> k) | (v << (64 - k));
}

__forceinline constexpr uint64_t bootmix(uint64_t v) {
    v ^= v >> 31;
    v *= 0x7A3B1C9D5E6F4028ull;
    v ^= v >> 29;
    v *= 0x4C15E2A39F7B8D61ull;
    v ^= v >> 37;
    return v;
}

__forceinline constexpr uint64_t ExtractTimeSeed(const char* t) {
    uint64_t h = static_cast<uint64_t>((t[0] - '0') * 10 + (t[1] - '0'));
    uint64_t m = static_cast<uint64_t>((t[3] - '0') * 10 + (t[4] - '0'));
    uint64_t s = static_cast<uint64_t>((t[6] - '0') * 10 + (t[7] - '0'));
    uint64_t v = (h * 3600ull + m * 60ull + s);
    v ^= 0x5A8E3F1B7C4D6029ull;
    v = bootmix(v);
    return v;
}

__forceinline constexpr uint64_t ExtractDateSeed(const char* d) {
    uint64_t v = 0;
    for (int i = 0; i < 11; ++i)
        v = v * 131ull + static_cast<uint64_t>(d[i]);
    v = bootmix(v);
    return v;
}

constexpr uint64_t BUILD_ENTROPY =
    bootmix(ExtractTimeSeed(__TIME__) ^ ExtractDateSeed(__DATE__) ^ 0x3E7A9C1D5B2F4068ull);

__forceinline constexpr uint64_t K(uint64_t slot) {
    uint64_t v = slot ^ BUILD_ENTROPY;
    v ^= v >> 33;
    v *= 0x6C4A7E1B3D8F5029ull;
    v ^= v >> 29;
    v *= 0x1E5B3A9D7C2F6048ull;
    v ^= v >> 31;
    return v | 1ull;
}

__forceinline constexpr uint64_t cat1(uint64_t v) {
    v ^= v >> 33;
    v *= K(10);
    v ^= v >> 33;
    v *= K(11);
    v ^= v >> 33;
    return v;
}

__forceinline constexpr uint64_t cat2(uint64_t v) {
    v += K(20);
    v = (v ^ (v >> 30)) * K(21);
    v = (v ^ (v >> 27)) * K(22);
    v ^= v >> 31;
    return v;
}

__forceinline constexpr uint64_t cat3(uint64_t v) {
    v ^= v >> 17;
    v *= K(30);
    v ^= v >> 31;
    v *= K(31);
    v ^= v >> 23;
    return v;
}

__forceinline constexpr uint64_t cat4(uint64_t v) {
    v = rl(v, 23) ^ (v * K(40));
    v ^= rr(v, 17);
    v *= K(41);
    v ^= v >> 29;
    return v;
}

__forceinline constexpr uint64_t cat5(uint64_t v) {
    v += K(50);
    v ^= rl(v, 13);
    v *= K(51);
    v ^= rr(v, 7);
    v += K(52);
    v ^= v >> 19;
    return v;
}

__forceinline constexpr uint64_t cat6(uint64_t v) {
    v *= K(60);
    v ^= rl(v, 37);
    v += K(61);
    v ^= rr(v, 11);
    v *= K(62);
    v ^= v >> 25;
    return v;
}

__forceinline constexpr uint64_t cat7(uint64_t v) {
    v ^= K(70);
    v = rl(v, 41) ^ (v >> 19);
    v *= K(71);
    v ^= rr(v, 29);
    v += K(72);
    v ^= v >> 13;
    return v;
}

__forceinline constexpr uint64_t cat8(uint64_t v) {
    v += K(80);
    v ^= rl(v, 19);
    v *= K(81);
    v ^= rr(v, 23);
    v += K(82);
    v ^= v >> 37;
    return v;
}

__forceinline constexpr uint64_t cat9(uint64_t v) {
    v *= K(90);
    v ^= rl(v, 7) ^ rr(v, 31);
    v += K(91);
    v ^= v >> 41;
    v *= K(92);
    v ^= rl(v, 3);
    return v;
}

__forceinline constexpr uint64_t cat10(uint64_t v) {
    v ^= K(100);
    v = rl(v, 53) + (v ^ rr(v, 11));
    v *= K(101);
    v ^= v >> 47;
    v += K(102);
    v ^= rr(v, 5);
    return v;
}

__forceinline constexpr uint64_t spl1(uint64_t v, uint64_t sel) {
    switch (sel & 7) {
    case 0: v = cat1(rl(v, 5)) ^ cat6(rr(v, 11)); break;
    case 1: v = cat2(rr(v, 7)) ^ cat7(rl(v, 13)); break;
    case 2: v = cat3(rl(v, 11)) ^ cat8(rr(v, 3)); break;
    case 3: v = cat4(rr(v, 13)) ^ cat9(rl(v, 7)); break;
    case 4: v = cat5(rl(v, 17)) ^ cat10(rr(v, 5)); break;
    case 5: v = cat6(rr(v, 19)) ^ cat1(rl(v, 3)); break;
    case 6: v = cat9(rl(v, 23)) ^ cat2(rr(v, 9)); break;
    case 7: v = cat10(rr(v, 29)) ^ cat3(rl(v, 11)); break;
    }
    return v;
}

__forceinline constexpr uint64_t spl2(uint64_t v, uint64_t sel) {
    switch (sel & 7) {
    case 0: v = cat9(rl(v, 3)) ^ cat4(rr(v, 17)); break;
    case 1: v = cat10(rr(v, 5)) ^ cat5(rl(v, 19)); break;
    case 2: v = cat1(rl(v, 7)) ^ cat6(rr(v, 23)); break;
    case 3: v = cat2(rr(v, 9)) ^ cat7(rl(v, 29)); break;
    case 4: v = cat3(rl(v, 11)) ^ cat8(rr(v, 31)); break;
    case 5: v = cat4(rr(v, 13)) ^ cat9(rl(v, 37)); break;
    case 6: v = cat5(rl(v, 15)) ^ cat10(rr(v, 41)); break;
    case 7: v = cat6(rr(v, 17)) ^ cat1(rl(v, 43)); break;
    }
    return v;
}

__forceinline constexpr uint64_t brn1(uint64_t v, uint64_t sel) {
    uint64_t a = spl1(v, sel);
    uint64_t b = spl2(rl(v, 17), sel >> 3);
    return a ^ rl(b, 11) ^ rr(a + b, 7);
}

__forceinline constexpr uint64_t CombineSeeds(uint64_t ts, uint64_t line, uint64_t counter) {
    uint64_t v = ts;
    v ^= cat2(line * K(200));
    v = cat1(v);
    v ^= cat3(counter * K(201));
    v = cat4(v);
    v ^= rl(line, 17) * K(202);
    v = cat5(v);
    v ^= rr(counter, 23) + K(203);
    v = cat6(v);
    return v;
}

__forceinline constexpr uint64_t ChainDerive(uint64_t seed, uint64_t index) {
    uint64_t v = seed ^ (index * K(300));

    v = cat1(v);
    v = cat2(v ^ (index << 3));
    v = spl1(v, v >> 5);
    v ^= rl(seed, static_cast<int>((index & 31) + 1));
    v = cat3(v);
    v = cat9(v ^ rr(index * K(301), 13));
    v = spl2(v, v >> 11);
    v ^= cat10(seed + index * 7ull);
    v = cat5(v);
    v = cat6(v ^ (index * index));
    v = brn1(v, v >> 7);
    v ^= cat3(rl(seed, static_cast<int>((index % 17) + 5)));
    v = cat7(v);
    v = cat8(v ^ cat4(index ^ (seed >> 3)));
    v = spl1(v, v >> 13);
    v ^= cat9(v + seed + index * K(302));
    v = cat10(v);
    v = cat2(v ^ cat6(seed ^ rr(index, 7)));
    v = spl2(v, v >> 17);
    v ^= cat7(v ^ (index * K(303)));
    v = cat3(v);
    v = brn1(v, v >> 19);
    v ^= cat8(seed + rl(index, static_cast<int>((seed % 29) + 2)));
    v = cat4(v);
    v = spl1(v, v >> 23);
    v ^= cat1(cat2(index * seed));
    v = cat5(v);
    v = cat6(v ^ cat9(seed ^ cat10(index)));
    v = spl2(v, v >> 29);
    v ^= cat7(rl(v, 11) ^ (index + K(304)));
    v = cat8(v);
    v = brn1(v, v >> 31);
    v ^= cat9(v ^ cat5(seed * (index + 1ull)));
    v = cat10(v);
    v ^= cat3(cat6(seed) ^ cat7(index));
    v = cat4(v);
    v ^= cat8(cat1(v) ^ cat2(seed ^ index));
    v = cat5(v);

    return v;
}

}
}

#define RAWLEN_TIME_SEED ::Rawlen::Random::ExtractTimeSeed(__TIME__)
#define RAWLEN_DATE_SEED ::Rawlen::Random::ExtractDateSeed(__DATE__)
#define RAWLEN_SEED ::Rawlen::Random::CombineSeeds( \
    RAWLEN_TIME_SEED ^ RAWLEN_DATE_SEED, \
    static_cast<uint64_t>(__LINE__), \
    static_cast<uint64_t>(__COUNTER__))