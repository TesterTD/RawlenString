#pragma once

#include "RandomManager.hpp"
#include <cstdint>
#include <cstddef>
#include <utility>

namespace Rawlen {

namespace Opaque {

__forceinline bool True1(uint64_t v) {
    volatile uint64_t a = v;
    volatile uint64_t b = v + 1;
    volatile uint64_t c = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
    volatile uint64_t d = c & 1ull;
    return d == 0;
}

__forceinline bool True2(uint64_t a, uint64_t b) {
    volatile uint64_t x = a | b;
    volatile uint64_t y = a & b;
    return static_cast<uint64_t>(x) >= static_cast<uint64_t>(y);
}

__forceinline bool True3(uint64_t v) {
    volatile uint64_t x = v;
    volatile uint64_t y = v;
    volatile uint64_t z = static_cast<uint64_t>(x) ^ static_cast<uint64_t>(y);
    return static_cast<uint64_t>(z) == 0;
}

__forceinline bool True4(uint64_t v) {
    volatile uint64_t x = v | 1ull;
    return static_cast<uint64_t>(x) > 0;
}

__forceinline bool True5(uint64_t v) {
    volatile uint64_t x = v;
    volatile uint64_t y = ~x;
    volatile uint64_t z = static_cast<uint64_t>(x) & static_cast<uint64_t>(y);
    return static_cast<uint64_t>(z) == 0;
}

__forceinline bool False1(uint64_t v) {
    volatile int64_t x = static_cast<int64_t>(v & 0xFF);
    volatile int64_t r = static_cast<int64_t>(x) * static_cast<int64_t>(x);
    return static_cast<int64_t>(r) < 0;
}

__forceinline bool False2(uint64_t v) {
    volatile uint64_t x = v;
    volatile uint64_t y = v;
    volatile uint64_t z = static_cast<uint64_t>(x) ^ static_cast<uint64_t>(y);
    return static_cast<uint64_t>(z) != 0;
}

__forceinline bool False3(uint64_t v) {
    volatile uint64_t x = v & 0xFFFFull;
    volatile uint64_t r = static_cast<uint64_t>(x);
    return r > 0x10000ull;
}

__forceinline bool False4(uint64_t v) {
    volatile uint64_t x = v;
    volatile uint64_t y = x;
    volatile uint64_t z = y;
    return static_cast<uint64_t>(x) != static_cast<uint64_t>(z);
}

__forceinline bool False5(uint64_t a, uint64_t b) {
    volatile uint64_t x = a + b;
    volatile uint64_t y = a + b;
    return static_cast<uint64_t>(x) != static_cast<uint64_t>(y);
}

__forceinline bool False6(uint64_t v) {
    volatile uint64_t x = v ^ v;
    return static_cast<uint64_t>(x) > 0;
}

__forceinline bool False7(uint64_t v) {
    volatile uint64_t x = v;
    volatile uint64_t y = x | x;
    return static_cast<uint64_t>(x) != static_cast<uint64_t>(y);
}

}

namespace Trampoline {

__forceinline uint64_t J0(uint64_t v) { return Random::cat1(v); }
__forceinline uint64_t J1(uint64_t v) { return Random::cat3(v); }
__forceinline uint64_t J2(uint64_t v) { return Random::cat5(v); }
__forceinline uint64_t J3(uint64_t v) { return Random::cat7(v); }
__forceinline uint64_t J4(uint64_t v) { return Random::cat9(v); }
__forceinline uint64_t J5(uint64_t v) { return Random::cat2(v); }
__forceinline uint64_t J6(uint64_t v) { return Random::cat4(v); }
__forceinline uint64_t J7(uint64_t v) { return Random::cat6(v); }

using TrampolineFn = uint64_t(*)(uint64_t);
inline volatile TrampolineFn Table[8] = { J0, J1, J2, J3, J4, J5, J6, J7 };

__forceinline uint64_t Dispatch(uint64_t v, uint64_t sel) {
    volatile auto fn = Table[sel & 7];
    return fn(v);
}

}

namespace Crypto {

__forceinline constexpr uint8_t EncryptByte(uint8_t b, uint64_t key) {
    uint8_t k0 = static_cast<uint8_t>(key);
    uint8_t k1 = static_cast<uint8_t>(key >> 8);
    uint8_t k2 = static_cast<uint8_t>(key >> 16);
    uint8_t k3 = static_cast<uint8_t>(key >> 24);
    uint8_t k4 = static_cast<uint8_t>(key >> 32);
    uint8_t k5 = static_cast<uint8_t>(key >> 40);
    uint8_t k6 = static_cast<uint8_t>(key >> 48);
    uint8_t k7 = static_cast<uint8_t>(key >> 56);
    b ^= k0;
    b = static_cast<uint8_t>(b + k1);
    b ^= k2;
    b = static_cast<uint8_t>(b + k3);
    b ^= k4;
    b = static_cast<uint8_t>(b + k5);
    b ^= k6;
    b = static_cast<uint8_t>(b + k7);
    b = static_cast<uint8_t>((b << 3) | (b >> 5));
    b ^= k3;
    b = static_cast<uint8_t>(b + k0);
    b ^= k5;
    b = static_cast<uint8_t>((b >> 2) | (b << 6));
    b = static_cast<uint8_t>(b + k7);
    b ^= k1;
    b = static_cast<uint8_t>(b + k4);
    b ^= k6;
    b = static_cast<uint8_t>((b << 5) | (b >> 3));
    b ^= k2;
    return b;
}

__forceinline constexpr uint8_t DecryptByte(uint8_t b, uint64_t key) {
    uint8_t k0 = static_cast<uint8_t>(key);
    uint8_t k1 = static_cast<uint8_t>(key >> 8);
    uint8_t k2 = static_cast<uint8_t>(key >> 16);
    uint8_t k3 = static_cast<uint8_t>(key >> 24);
    uint8_t k4 = static_cast<uint8_t>(key >> 32);
    uint8_t k5 = static_cast<uint8_t>(key >> 40);
    uint8_t k6 = static_cast<uint8_t>(key >> 48);
    uint8_t k7 = static_cast<uint8_t>(key >> 56);
    b ^= k2;
    b = static_cast<uint8_t>((b >> 5) | (b << 3));
    b ^= k6;
    b = static_cast<uint8_t>(b - k4);
    b ^= k1;
    b = static_cast<uint8_t>(b - k7);
    b = static_cast<uint8_t>((b << 2) | (b >> 6));
    b ^= k5;
    b = static_cast<uint8_t>(b - k0);
    b ^= k3;
    b = static_cast<uint8_t>((b >> 3) | (b << 5));
    b = static_cast<uint8_t>(b - k7);
    b ^= k6;
    b = static_cast<uint8_t>(b - k5);
    b ^= k4;
    b = static_cast<uint8_t>(b - k3);
    b ^= k2;
    b = static_cast<uint8_t>(b - k1);
    b ^= k0;
    return b;
}

template<typename CharT>
__forceinline constexpr CharT EncryptChar(CharT ch, uint64_t key) {
    if constexpr (sizeof(CharT) == 1) {
        return static_cast<CharT>(EncryptByte(static_cast<uint8_t>(ch), key));
    } else if constexpr (sizeof(CharT) == 2) {
        uint8_t lo = static_cast<uint8_t>(static_cast<uint16_t>(ch) & 0xFF);
        uint8_t hi = static_cast<uint8_t>((static_cast<uint16_t>(ch) >> 8) & 0xFF);
        lo = EncryptByte(lo, key);
        hi = EncryptByte(hi, Random::cat1(key ^ Random::K(500)));
        return static_cast<CharT>(static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8));
    } else {
        uint32_t val = static_cast<uint32_t>(ch);
        uint8_t b0 = EncryptByte(static_cast<uint8_t>(val & 0xFF), key);
        uint8_t b1 = EncryptByte(static_cast<uint8_t>((val >> 8) & 0xFF),
                                  Random::cat1(key ^ Random::K(501)));
        uint8_t b2 = EncryptByte(static_cast<uint8_t>((val >> 16) & 0xFF),
                                  Random::cat2(key ^ Random::K(502)));
        uint8_t b3 = EncryptByte(static_cast<uint8_t>((val >> 24) & 0xFF),
                                  Random::cat3(key ^ Random::K(503)));
        return static_cast<CharT>(
            static_cast<uint32_t>(b0)
            | (static_cast<uint32_t>(b1) << 8)
            | (static_cast<uint32_t>(b2) << 16)
            | (static_cast<uint32_t>(b3) << 24));
    }
}

template<typename CharT>
__forceinline constexpr CharT DecryptChar(CharT ch, uint64_t key) {
    if constexpr (sizeof(CharT) == 1) {
        return static_cast<CharT>(DecryptByte(static_cast<uint8_t>(ch), key));
    } else if constexpr (sizeof(CharT) == 2) {
        uint8_t lo = static_cast<uint8_t>(static_cast<uint16_t>(ch) & 0xFF);
        uint8_t hi = static_cast<uint8_t>((static_cast<uint16_t>(ch) >> 8) & 0xFF);
        lo = DecryptByte(lo, key);
        hi = DecryptByte(hi, Random::cat1(key ^ Random::K(500)));
        return static_cast<CharT>(static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8));
    } else {
        uint32_t val = static_cast<uint32_t>(ch);
        uint8_t b0 = DecryptByte(static_cast<uint8_t>(val & 0xFF), key);
        uint8_t b1 = DecryptByte(static_cast<uint8_t>((val >> 8) & 0xFF),
                                  Random::cat1(key ^ Random::K(501)));
        uint8_t b2 = DecryptByte(static_cast<uint8_t>((val >> 16) & 0xFF),
                                  Random::cat2(key ^ Random::K(502)));
        uint8_t b3 = DecryptByte(static_cast<uint8_t>((val >> 24) & 0xFF),
                                  Random::cat3(key ^ Random::K(503)));
        return static_cast<CharT>(
            static_cast<uint32_t>(b0)
            | (static_cast<uint32_t>(b1) << 8)
            | (static_cast<uint32_t>(b2) << 16)
            | (static_cast<uint32_t>(b3) << 24));
    }
}

}

template<typename CharT, size_t N>
struct DecryptedBuffer {
    CharT data[N]{};
    __forceinline operator const CharT*() const { return data; }
};

namespace Distant {

template<uint64_t Seed, typename CharT, size_t N>
__declspec(noinline) void DistantIsland1(const CharT* enc, CharT* out) {
    volatile uint64_t px = Seed;
    for (volatile size_t i = 0; i < N; ++i) {
        uint64_t lpx = static_cast<uint64_t>(px);
        uint64_t li = static_cast<size_t>(i);
        uint64_t dk = Random::ChainDerive(lpx, li);
        out[li] = Crypto::DecryptChar(enc[li], dk);
        px = Trampoline::Dispatch(lpx ^ li, li);
    }
}

template<uint64_t Seed, typename CharT, size_t N>
__declspec(noinline) void DistantIsland2(const CharT* enc, CharT* out) {
    volatile uint64_t px = Random::brn1(Seed, Seed >> 3);
    for (volatile size_t i = 0; i < N; ++i) {
        uint64_t lpx = static_cast<uint64_t>(px);
        uint64_t li = static_cast<size_t>(i);
        out[li] = Crypto::DecryptChar(enc[li], Random::ChainDerive(Seed, li));
        px = Random::cat8(lpx + li);
    }
}

template<uint64_t Seed, typename CharT, size_t N>
__declspec(noinline) void DistantIsland3(const CharT* enc, CharT* out) {
    volatile uint64_t px = Random::cat5(Seed);
    for (volatile size_t i = 0; i < N; ++i) {
        uint64_t lpx = static_cast<uint64_t>(px);
        uint64_t li = static_cast<size_t>(i);
        out[li] = Crypto::DecryptChar(enc[li], Random::ChainDerive(Seed, li));
        px = Random::spl2(lpx ^ li, li);
    }
}

template<uint64_t Seed, typename CharT, size_t N>
__declspec(noinline) void DistantIsland4(const CharT* enc, CharT* out) {
    volatile uint64_t px = Random::cat10(Seed ^ Random::K(810));
    volatile uint64_t acc = Random::cat2(Seed);
    for (volatile size_t i = 0; i < N; ++i) {
        uint64_t lpx = static_cast<uint64_t>(px);
        uint64_t lacc = static_cast<uint64_t>(acc);
        uint64_t li = static_cast<size_t>(i);
        out[li] = Crypto::DecryptChar(enc[li], Random::ChainDerive(Seed, li));
        px = Random::cat9(lpx ^ lacc);
        acc = Trampoline::Dispatch(lacc + li, li);
    }
}

template<uint64_t Seed>
__declspec(noinline) uint64_t DistantIslandVal1(uint64_t enc) {
    volatile uint64_t px = Seed;
    uint64_t lpx = static_cast<uint64_t>(px);
    uint64_t k0 = Random::ChainDerive(lpx, 0);
    uint64_t k1 = Random::ChainDerive(lpx, 1);
    uint64_t k2 = Random::ChainDerive(lpx, 2);
    volatile uint64_t r = enc ^ k0 ^ k1 ^ k2;
    return static_cast<uint64_t>(r);
}

template<uint64_t Seed>
__declspec(noinline) uint64_t DistantIslandVal2(uint64_t enc) {
    volatile uint64_t px = Random::cat7(Seed);
    volatile uint64_t r = enc ^ Random::ChainDerive(Seed, 0)
                               ^ Random::ChainDerive(Seed, 1)
                               ^ Random::ChainDerive(Seed, 2);
    return static_cast<uint64_t>(r);
}

template<uint64_t Seed>
__declspec(noinline) uint64_t DistantIslandVal3(uint64_t enc) {
    volatile uint64_t px = Random::cat5(Seed ^ Random::K(820));
    volatile uint64_t r = enc ^ Random::ChainDerive(Seed, 0)
                               ^ Random::ChainDerive(Seed, 1)
                               ^ Random::ChainDerive(Seed, 2);
    return static_cast<uint64_t>(r);
}

template<uint64_t Seed>
__declspec(noinline) uint64_t DistantIslandVal4(uint64_t enc) {
    volatile uint64_t px = Random::brn1(Seed, Random::K(830));
    volatile uint64_t r = enc ^ Random::ChainDerive(Seed, 0)
                               ^ Random::ChainDerive(Seed, 1)
                               ^ Random::ChainDerive(Seed, 2);
    return static_cast<uint64_t>(r);
}

}

template<uint64_t Seed, typename CharT, size_t N>
struct EncryptedString {
    CharT enc[N]{};

    template<size_t... I>
    __forceinline constexpr EncryptedString(const CharT(&str)[N], std::index_sequence<I...>)
        : enc{ Crypto::EncryptChar(str[I], Random::ChainDerive(Seed, I))... } {}

    __forceinline DecryptedBuffer<CharT, N> decrypt() const {
        return decryptImpl(std::make_index_sequence<N>{});
    }

private:
    template<size_t... I>
    __forceinline DecryptedBuffer<CharT, N> decryptImpl(std::index_sequence<I...>) const {
        DecryptedBuffer<CharT, N> buf{};

        volatile uint64_t noise = 0;
        volatile uint64_t chain = 0;
        volatile uint64_t selfref = 0;
        volatile uint64_t stk[16];
        volatile int bogus_ctr1 = 0;
        volatile int bogus_ctr2 = 0;
        volatile int bogus_ctr3 = 0;

        uint64_t rs = Seed ^ static_cast<uint64_t>(noise);

        stk[0] = rs;
        stk[1] = rs ^ Seed;
        stk[2] = Trampoline::Dispatch(rs, 0);
        stk[3] = Trampoline::Dispatch(rs, 3);

        volatile uint32_t state = 0x1001u;
        volatile bool running = true;

        while (static_cast<bool>(running)) {
            switch (static_cast<uint32_t>(state)) {

            case 0x1001u: {
                chain = rs * Random::K(600);
                selfref = Trampoline::Dispatch(rs, rs >> 5);
                if (Opaque::True4(rs)) {
                    state = 0x10A1u;
                } else {
                    state = 0xAA01u;
                }
                break;
            }

            case 0x10A1u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                stk[(lc >> 3) & 15] = lc ^ rs;
                while (bogus_ctr1) {
                    stk[(lc >> 7) & 15] = Random::cat1(lc);
                    bogus_ctr1 = static_cast<int>(bogus_ctr1) - 1;
                }
                if (Opaque::True1(rs)) {
                    state = 0x1002u;
                } else {
                    state = 0xAA01u;
                }
                break;
            }

            case 0x1002u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t mixed = Trampoline::Dispatch(lc ^ ls, lc >> 3);
                chain = mixed;
                if (Opaque::True5(mixed)) {
                    state = 0x10B2u;
                } else {
                    state = 0xBB01u;
                }
                break;
            }

            case 0x10B2u: {
                uint64_t mixed = static_cast<uint64_t>(chain);
                stk[(mixed >> 4) & 15] = mixed;
                if (Opaque::False1(rs)) {
                    state = 0xBB01u;
                } else {
                    state = 0x1003u;
                }
                break;
            }

            case 0x1003u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::spl1(lc, lc >> 7) ^ Trampoline::Dispatch(rs, 2);
                if (Opaque::True4(lc)) {
                    state = 0x10A3u;
                } else {
                    state = 0xCC01u;
                }
                break;
            }

            case 0x10A3u: {
                while (bogus_ctr2) {
                    chain = Random::cat3(static_cast<uint64_t>(chain));
                    bogus_ctr2 = static_cast<int>(bogus_ctr2) - 1;
                }
                if (Opaque::True2(rs, static_cast<uint64_t>(chain))) {
                    state = 0x1004u;
                } else {
                    state = 0xCC01u;
                }
                break;
            }

            case 0x1004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t prev = lc;
                chain = Random::brn1(lc ^ ls, rs);
                selfref = Trampoline::Dispatch(prev, prev >> 11);
                if (Opaque::False6(rs)) {
                    state = 0xDD01u;
                } else {
                    state = 0x10A4u;
                }
                break;
            }

            case 0x10A4u: {
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t lc = static_cast<uint64_t>(chain);
                stk[(ls >> 5) & 15] = ls ^ lc;
                if (Opaque::False2(rs)) {
                    state = 0xDD01u;
                } else {
                    state = 0x1005u;
                }
                break;
            }

            case 0x1005u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t combined = lc ^ ls ^ static_cast<uint64_t>(stk[rs & 15]);
                chain = Trampoline::Dispatch(combined, combined >> 4);
                if (Opaque::True5(rs)) {
                    state = 0x10A5u;
                } else {
                    state = 0xEE01u;
                }
                break;
            }

            case 0x10A5u: {
                while (bogus_ctr3) {
                    selfref = Random::cat9(static_cast<uint64_t>(selfref));
                    bogus_ctr3 = static_cast<int>(bogus_ctr3) - 1;
                }
                if (Opaque::True3(rs)) {
                    state = 0x1006u;
                } else {
                    state = 0xEE01u;
                }
                break;
            }

            case 0x1006u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                selfref = Random::cat10(lc) ^ Random::cat2(ls);
                chain = Trampoline::Dispatch(lc ^ ls, 5);
                if (Opaque::False7(rs)) {
                    state = 0xFF01u;
                } else {
                    state = 0x10A6u;
                }
                break;
            }

            case 0x10A6u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                if (Opaque::False3(rs)) {
                    state = 0xFF01u;
                } else {
                    state = 0x1007u;
                }
                break;
            }

            case 0x1007u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(lc >> 6) & 15] = lc ^ ls;
                chain = Random::spl2(lc, ls >> 3);
                if (Opaque::True4(ls)) {
                    state = 0x10A7u;
                } else {
                    state = 0x1008u;
                }
                break;
            }

            case 0x10A7u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                selfref = Trampoline::Dispatch(ls, 7) ^ lc;
                state = 0x1008u;
                break;
            }

            case 0x1008u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t extra = lc ^ ls;
                noise = extra;
                if (Opaque::False4(rs)) {
                    state = 0xAA01u;
                } else {
                    state = 0x10A8u;
                }
                break;
            }

            case 0x10A8u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                if (Opaque::False5(rs, lc)) {
                    state = 0xBB01u;
                } else if (Opaque::False6(lc)) {
                    state = 0xAB01u;
                } else {
                    state = 0x7F01u;
                }
                break;
            }

            case 0x7F01u: {
                uint64_t n = static_cast<uint64_t>(noise);
                volatile uint64_t mod_extra = n ^ n;
                uint64_t me = static_cast<uint64_t>(mod_extra);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::ChainDerive(rs, I) ^ me)), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0x7F0Fu: {
                running = false;
                break;
            }

            case 0xAA01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat1(lc) ^ Random::cat7(lc >> 3);
                selfref = Trampoline::Dispatch(lc, 1);
                state = 0xAA0Au;
                break;
            }

            case 0xAA0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                stk[(lc >> 2) & 15] = lc;
                state = 0xAA02u;
                break;
            }

            case 0xAA02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl1(lc ^ ls, lc);
                selfref = Random::cat9(ls ^ lc);
                state = 0xAA03u;
                break;
            }

            case 0xAA03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc, ls);
                stk[(ls >> 4) & 15] = ls ^ lc;
                state = 0xAA04u;
                break;
            }

            case 0xAA04u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Trampoline::Dispatch(lc ^ ls, lc >> 5);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::cat5(fk ^ I))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xBB01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat3(lc) ^ Trampoline::Dispatch(lc, 4);
                state = 0xBB0Au;
                break;
            }

            case 0xBB0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::cat8(lc);
                state = 0xBB02u;
                break;
            }

            case 0xBB02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl2(lc, ls);
                selfref = Trampoline::Dispatch(ls, 6) ^ lc;
                state = 0xBB03u;
                break;
            }

            case 0xBB03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat10(lc ^ ls);
                stk[(lc >> 3) & 15] = ls;
                state = 0xBB0Bu;
                break;
            }

            case 0xBB0Bu: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(ls >> 7) & 15] = lc ^ ls;
                chain = Random::cat4(lc);
                state = 0xBB05u;
                break;
            }

            case 0xBB05u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Random::brn1(lc, ls) ^ Trampoline::Dispatch(lc, 2);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::cat2(fk + I))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xCC01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Trampoline::Dispatch(lc, 0) ^ Random::cat5(lc);
                state = 0xCC0Au;
                break;
            }

            case 0xCC0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::cat6(lc >> 7);
                state = 0xCC02u;
                break;
            }

            case 0xCC02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat7(lc ^ ls);
                selfref = Trampoline::Dispatch(ls, 3);
                state = 0xCC0Bu;
                break;
            }

            case 0xCC0Bu: {
                uint64_t lc = static_cast<uint64_t>(chain);
                stk[(lc >> 5) & 15] = lc;
                state = 0xCC03u;
                break;
            }

            case 0xCC03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl1(lc, ls >> 5);
                state = 0xCC04u;
                break;
            }

            case 0xCC04u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Random::cat4(lc) ^ Random::cat10(ls);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::cat8(fk * (I + 1)))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xDD01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat9(lc) ^ Trampoline::Dispatch(lc, 7);
                state = 0xDD0Au;
                break;
            }

            case 0xDD0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::spl2(lc, lc >> 11);
                state = 0xDD02u;
                break;
            }

            case 0xDD02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc ^ ls, lc);
                selfref = Trampoline::Dispatch(ls ^ lc, 5);
                state = 0xDD03u;
                break;
            }

            case 0xDD03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat1(lc) ^ Random::cat3(ls);
                stk[(lc >> 4) & 15] = ls;
                state = 0xDD0Bu;
                break;
            }

            case 0xDD0Bu: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(ls >> 6) & 15] = lc ^ ls;
                chain = Trampoline::Dispatch(lc, 1);
                state = 0xDD05u;
                break;
            }

            case 0xDD05u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Random::brn1(lc, ls);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::cat6(fk ^ I))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xEE01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Trampoline::Dispatch(lc, 6) ^ Random::cat2(lc);
                state = 0xEE0Au;
                break;
            }

            case 0xEE0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::spl1(lc, lc >> 3);
                state = 0xEE02u;
                break;
            }

            case 0xEE02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat8(lc ^ ls);
                selfref = Trampoline::Dispatch(ls, 0) ^ Random::cat1(lc);
                state = 0xEE03u;
                break;
            }

            case 0xEE03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc, ls) ^ Trampoline::Dispatch(lc ^ ls, 4);
                stk[(lc >> 3) & 15] = ls ^ lc;
                state = 0xEE0Bu;
                break;
            }

            case 0xEE0Bu: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat5(lc) ^ Random::cat9(ls);
                selfref = Trampoline::Dispatch(lc, 2);
                state = 0xEE05u;
                break;
            }

            case 0xEE05u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = lc ^ ls;
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::spl1(fk, I))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xFF01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat10(lc) ^ Trampoline::Dispatch(lc, 3);
                state = 0xFF0Au;
                break;
            }

            case 0xFF0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::cat4(lc ^ rs);
                state = 0xFF02u;
                break;
            }

            case 0xFF02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl2(lc, ls >> 7);
                selfref = Random::brn1(ls, lc) ^ Trampoline::Dispatch(lc, 1);
                state = 0xFF03u;
                break;
            }

            case 0xFF03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat6(lc ^ ls) ^ Random::cat3(ls);
                stk[(ls >> 5) & 15] = lc;
                state = 0xFF04u;
                break;
            }

            case 0xFF04u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Trampoline::Dispatch(lc ^ ls, 7);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::cat7(fk + I))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xAB01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat2(lc) ^ Trampoline::Dispatch(lc, 5);
                selfref = Random::cat7(lc ^ rs);
                state = 0xAB0Au;
                break;
            }

            case 0xAB0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc, ls) ^ Random::cat4(ls);
                stk[(lc >> 4) & 15] = lc ^ ls;
                state = 0xAB02u;
                break;
            }

            case 0xAB02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                selfref = Trampoline::Dispatch(ls, 2) ^ Random::cat8(lc);
                chain = Random::cat6(lc ^ ls);
                state = 0xAB03u;
                break;
            }

            case 0xAB03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Random::spl2(lc, ls >> 3) ^ Trampoline::Dispatch(lc, 0);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::cat10(fk ^ I))), ...);
                state = 0x7F0Fu;
                break;
            }

            case 0xAC01u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat8(lc) ^ Random::cat1(lc >> 5);
                selfref = Trampoline::Dispatch(lc, 3);
                state = 0xAC0Au;
                break;
            }

            case 0xAC0Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl1(lc, ls >> 9);
                selfref = Random::brn1(ls, lc) ^ Random::cat9(lc);
                state = 0xAC02u;
                break;
            }

            case 0xAC02u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(lc >> 7) & 15] = lc;
                chain = Random::cat10(lc ^ ls) ^ Trampoline::Dispatch(ls, 4);
                state = 0xAC03u;
                break;
            }

            case 0xAC03u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                uint64_t fk = Random::cat7(lc) ^ Random::cat2(ls);
                ((buf.data[I] = Crypto::DecryptChar(enc[I], Random::spl2(fk, I))), ...);
                state = 0x7F0Fu;
                break;
            }

            default: {
                state = 0x7F0Fu;
                running = false;
                break;
            }

            }
        }

        uint64_t final_chain = static_cast<uint64_t>(chain);
        if (Opaque::False1(final_chain)) {
            goto str_island_1;
        }
        if (Opaque::False4(final_chain)) {
            goto str_island_2;
        }
        if (Opaque::False6(final_chain)) {
            goto str_island_3;
        }
        if (Opaque::False7(final_chain)) {
            goto str_island_4;
        }

        return buf;

    str_island_1:
        {
            Distant::DistantIsland1<Seed, CharT, N>(enc, buf.data);
            volatile uint64_t px = Random::cat1(rs);
            stk[(static_cast<uint64_t>(px) >> 3) & 15] = px;
            chain = Trampoline::Dispatch(static_cast<uint64_t>(px), 4);
            selfref = Random::brn1(static_cast<uint64_t>(chain), static_cast<uint64_t>(px));
            return buf;
        }

    str_island_2:
        {
            Distant::DistantIsland2<Seed, CharT, N>(enc, buf.data);
            volatile uint64_t px = Random::cat9(rs);
            stk[(static_cast<uint64_t>(px) >> 5) & 15] = px;
            chain = Random::spl2(static_cast<uint64_t>(px), static_cast<uint64_t>(px) >> 7);
            selfref = Trampoline::Dispatch(static_cast<uint64_t>(chain), 6);
            return buf;
        }

    str_island_3:
        {
            Distant::DistantIsland3<Seed, CharT, N>(enc, buf.data);
            volatile uint64_t px = Random::cat5(rs);
            stk[(static_cast<uint64_t>(px) >> 4) & 15] = px;
            chain = Random::cat7(static_cast<uint64_t>(px));
            selfref = Random::brn1(static_cast<uint64_t>(chain), rs);
            return buf;
        }

    str_island_4:
        {
            Distant::DistantIsland4<Seed, CharT, N>(enc, buf.data);
            volatile uint64_t px = Random::cat10(rs ^ Random::K(810));
            stk[(static_cast<uint64_t>(px) >> 6) & 15] = px;
            chain = Trampoline::Dispatch(static_cast<uint64_t>(px), 1);
            selfref = Random::cat3(static_cast<uint64_t>(chain) ^ rs);
            return buf;
        }
    }
};

template<uint64_t Seed>
struct EncryptedValue {
    uint64_t enc;

    __forceinline constexpr EncryptedValue(uint64_t v)
        : enc(v ^ Random::ChainDerive(Seed, 0)
                ^ Random::ChainDerive(Seed, 1)
                ^ Random::ChainDerive(Seed, 2)) {}

    __forceinline uint64_t decrypt() const {
        volatile uint64_t noise = 0;
        volatile uint64_t chain = 0;
        volatile uint64_t selfref = 0;
        volatile uint64_t stk[8];
        volatile int bogus_ctr1 = 0;
        volatile int bogus_ctr2 = 0;

        uint64_t rs = Seed ^ static_cast<uint64_t>(noise);

        stk[0] = rs;
        stk[1] = Trampoline::Dispatch(rs, 1);

        volatile uint32_t state = 0x2001u;
        volatile bool running = true;
        volatile uint64_t result = 0;

        while (static_cast<bool>(running)) {
            switch (static_cast<uint32_t>(state)) {

            case 0x2001u: {
                chain = rs * Random::K(700);
                selfref = Trampoline::Dispatch(rs, rs >> 4);
                if (Opaque::True4(rs)) {
                    state = 0x20A1u;
                } else {
                    state = 0xA001u;
                }
                break;
            }

            case 0x20A1u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                stk[(lc >> 3) & 7] = lc;
                while (bogus_ctr1) {
                    stk[(lc >> 5) & 7] = Random::cat1(lc);
                    bogus_ctr1 = static_cast<int>(bogus_ctr1) - 1;
                }
                if (Opaque::True1(rs)) {
                    state = 0x2002u;
                } else {
                    state = 0xA001u;
                }
                break;
            }

            case 0x2002u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Trampoline::Dispatch(lc ^ ls, lc >> 3);
                state = 0x20A2u;
                break;
            }

            case 0x20A2u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                selfref = Random::spl1(ls, lc >> 7);
                if (Opaque::False2(rs)) {
                    state = 0xB001u;
                } else {
                    state = 0x2003u;
                }
                break;
            }

            case 0x2003u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc, ls);
                selfref = Trampoline::Dispatch(ls ^ lc, 5);
                state = 0x20A3u;
                break;
            }

            case 0x20A3u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(lc >> 4) & 7] = lc ^ ls;
                while (bogus_ctr2) {
                    chain = Random::cat7(static_cast<uint64_t>(chain));
                    bogus_ctr2 = static_cast<int>(bogus_ctr2) - 1;
                }
                if (Opaque::True3(rs)) {
                    state = 0x2004u;
                } else {
                    state = 0xC001u;
                }
                break;
            }

            case 0x2004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat4(lc) ^ Random::cat8(ls);
                state = 0x20A4u;
                break;
            }

            case 0x20A4u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                selfref = Trampoline::Dispatch(lc, 2) ^ ls;
                if (Opaque::False3(lc)) {
                    state = 0xD001u;
                } else {
                    state = 0x2005u;
                }
                break;
            }

            case 0x2005u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(ls >> 3) & 7] = lc ^ ls;
                noise = lc ^ ls;
                if (Opaque::False4(rs)) {
                    state = 0xA001u;
                } else {
                    state = 0x20A5u;
                }
                break;
            }

            case 0x20A5u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                if (Opaque::False5(rs, lc)) {
                    state = 0xB001u;
                } else if (Opaque::False6(rs)) {
                    state = 0xE001u;
                } else {
                    state = 0x2F01u;
                }
                break;
            }

            case 0x2F01u: {
                uint64_t n = static_cast<uint64_t>(noise);
                volatile uint64_t mod_extra = n ^ n;
                uint64_t me = static_cast<uint64_t>(mod_extra);
                result = enc ^ Random::ChainDerive(rs, 0)
                             ^ Random::ChainDerive(rs, 1)
                             ^ Random::ChainDerive(rs, 2)
                             ^ me;
                state = 0x2F0Fu;
                break;
            }

            case 0x2F0Fu: {
                running = false;
                break;
            }

            case 0xA001u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat1(lc) ^ Trampoline::Dispatch(lc, 0);
                selfref = Random::cat5(lc ^ rs);
                state = 0xA002u;
                break;
            }

            case 0xA002u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl1(lc, ls);
                selfref = Random::cat9(ls ^ lc);
                state = 0xA00Au;
                break;
            }

            case 0xA00Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc, ls);
                stk[(lc >> 3) & 7] = ls;
                state = 0xA004u;
                break;
            }

            case 0xA004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                result = enc ^ Random::cat1(lc) ^ Random::cat3(ls) ^ Random::cat5(lc ^ ls);
                state = 0x2F0Fu;
                break;
            }

            case 0xB001u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat7(lc) ^ Trampoline::Dispatch(lc, 3);
                selfref = Random::cat2(lc);
                state = 0xB00Au;
                break;
            }

            case 0xB00Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl2(lc ^ ls, lc);
                selfref = Trampoline::Dispatch(ls, 7);
                state = 0xB003u;
                break;
            }

            case 0xB003u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat10(lc ^ ls);
                stk[(ls >> 4) & 7] = lc;
                state = 0xB004u;
                break;
            }

            case 0xB004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                result = enc ^ Random::cat7(lc) ^ Random::cat9(ls) ^ Random::cat2(lc ^ ls);
                state = 0x2F0Fu;
                break;
            }

            case 0xC001u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Trampoline::Dispatch(lc, 4) ^ Random::cat6(lc);
                state = 0xC00Au;
                break;
            }

            case 0xC00Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::spl1(lc, lc >> 5);
                state = 0xC002u;
                break;
            }

            case 0xC002u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::brn1(lc ^ ls, lc);
                selfref = Trampoline::Dispatch(ls, 1) ^ lc;
                state = 0xC003u;
                break;
            }

            case 0xC003u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat3(lc) ^ Random::cat8(ls);
                stk[(lc >> 5) & 7] = ls ^ lc;
                state = 0xC004u;
                break;
            }

            case 0xC004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                result = enc ^ Random::spl1(lc, ls) ^ Random::spl2(ls, lc >> 3);
                state = 0x2F0Fu;
                break;
            }

            case 0xD001u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat4(lc) ^ Trampoline::Dispatch(lc, 6);
                state = 0xD00Au;
                break;
            }

            case 0xD00Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                selfref = Random::cat10(lc ^ rs);
                state = 0xD002u;
                break;
            }

            case 0xD002u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::spl2(lc, ls >> 3);
                selfref = Random::brn1(ls, lc);
                state = 0xD003u;
                break;
            }

            case 0xD003u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(lc >> 6) & 7] = lc ^ ls;
                chain = Trampoline::Dispatch(lc, 0) ^ ls;
                state = 0xD004u;
                break;
            }

            case 0xD004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                result = enc ^ Random::cat6(lc ^ ls) ^ Random::cat1(lc) ^ Random::cat9(ls);
                state = 0x2F0Fu;
                break;
            }

            case 0xE001u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                chain = Random::cat5(lc) ^ Trampoline::Dispatch(lc, 2);
                selfref = Random::cat7(lc ^ rs);
                state = 0xE00Au;
                break;
            }

            case 0xE00Au: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                chain = Random::cat8(lc ^ ls);
                selfref = Trampoline::Dispatch(ls, 5) ^ Random::cat3(lc);
                state = 0xE003u;
                break;
            }

            case 0xE003u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                stk[(lc >> 3) & 7] = lc;
                chain = Random::spl1(lc, ls >> 5);
                state = 0xE004u;
                break;
            }

            case 0xE004u: {
                uint64_t lc = static_cast<uint64_t>(chain);
                uint64_t ls = static_cast<uint64_t>(selfref);
                result = enc ^ Random::cat10(lc ^ ls) ^ Random::cat2(lc) ^ Random::cat6(ls);
                state = 0x2F0Fu;
                break;
            }

            default: {
                state = 0x2F0Fu;
                running = false;
                break;
            }

            }
        }

        uint64_t final_chain = static_cast<uint64_t>(chain);
        if (Opaque::False1(final_chain)) {
            goto val_island_1;
        }
        if (Opaque::False4(final_chain)) {
            goto val_island_2;
        }
        if (Opaque::False6(final_chain)) {
            goto val_island_3;
        }
        if (Opaque::False7(final_chain)) {
            goto val_island_4;
        }

        return static_cast<uint64_t>(result);

    val_island_1:
        {
            result = Distant::DistantIslandVal1<Seed>(enc);
            volatile uint64_t px = Random::cat3(rs);
            stk[(static_cast<uint64_t>(px) >> 3) & 7] = px;
            chain = Trampoline::Dispatch(static_cast<uint64_t>(px), 2);
            return static_cast<uint64_t>(result);
        }

    val_island_2:
        {
            result = Distant::DistantIslandVal2<Seed>(enc);
            volatile uint64_t px = Random::cat7(rs);
            stk[(static_cast<uint64_t>(px) >> 4) & 7] = px;
            chain = Random::spl1(static_cast<uint64_t>(px), static_cast<uint64_t>(px) >> 5);
            return static_cast<uint64_t>(result);
        }

    val_island_3:
        {
            result = Distant::DistantIslandVal3<Seed>(enc);
            volatile uint64_t px = Random::cat5(rs);
            stk[(static_cast<uint64_t>(px) >> 5) & 7] = px;
            chain = Random::cat10(static_cast<uint64_t>(px));
            selfref = Trampoline::Dispatch(static_cast<uint64_t>(px), 0);
            return static_cast<uint64_t>(result);
        }

    val_island_4:
        {
            result = Distant::DistantIslandVal4<Seed>(enc);
            volatile uint64_t px = Random::brn1(rs, Random::K(830));
            stk[(static_cast<uint64_t>(px) >> 6) & 7] = px;
            chain = Random::cat2(static_cast<uint64_t>(px));
            selfref = Random::spl2(static_cast<uint64_t>(px), rs >> 9);
            return static_cast<uint64_t>(result);
        }
    }
};

}

#define RS(str) \
    ([]() -> decltype(auto) { \
        constexpr auto _e = ::Rawlen::EncryptedString< \
            RAWLEN_SEED, \
            std::decay_t<decltype(str[0])>, \
            sizeof(str) / sizeof(str[0])>( \
                str, \
                std::make_index_sequence<sizeof(str) / sizeof(str[0])>{}); \
        return _e.decrypt(); \
    }())

#define RV(val) \
    ([]() -> decltype(val) { \
        constexpr auto _e = ::Rawlen::EncryptedValue<RAWLEN_SEED>( \
            static_cast<uint64_t>(val)); \
        volatile uint64_t _d = _e.decrypt(); \
        return static_cast<decltype(val)>(_d); \
    }())

#define RVF(val) \
    ([]() -> decltype(val) { \
        constexpr int64_t _o = static_cast<int64_t>( \
            ::Rawlen::Random::ChainDerive(RAWLEN_SEED, 777) & 0xFFFF); \
        volatile auto _enc = static_cast<decltype(val)>((val) + _o); \
        volatile auto _off = static_cast<decltype(val)>(_o); \
        return static_cast<decltype(val)>(_enc - _off); \
    }())