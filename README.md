# RawlenString
Very powerful compile-time encryption of strings and constants with control flow obfuscation for C++17 (MSVC)

---

# Introduction
Building on existing projects such as xorstr and oxorany - each with its own advantages (the former being lightweight, the latter highly complex), RawlenString is a heavyweight tool for obfuscating and scrambling strings at compile time.

* All things considered, I think this is the perfect balance!

---

# Features
> Given that this can be observed:
* All encryption operations are performed at compile time (just like any other compiler)
* A unique identifier for each individual macro call using __TIME__, __DATE__, __LINE__, and __COUNTER__
* The decoding is implemented as a virtual finite-state machine with over 40 states...
* Volatile-based opaque predicates - conditions whose outcome is mathematically determined but opaque to the compiler
* TrampolineDispatcher is present - this essentially involves calling hash functions via a table of volatile pointers
* Unreachable code blocks (distant islands) with alternative decoding implementations primarily those for specific offsets, can be referred to as indirect handlers!
* Fake loops and variables that generate junk code
* Each compilation generates a unique control flow graph

## What It Supports

| Category | Details |
|---|---|
| Narrow strings | `char*` |
| Wide strings | `wchar_t*` |
| Unicode strings | `char16_t*`, `char32_t*` |
| Integers | `int8_t` `int16_t` `int32_t` `int64_t` `uint8_t` `uint16_t` `uint32_t` `uint64_t` |
| Windows types | `DWORD` `WORD` `BYTE` `HANDLE` and similar |
| HEX constants | `0xFF`, `0x1234567887654321` |
| Enumerations | `enum`, `enum class` |
| Macros | `#define MY_CONST 42` |
| Pointers | `NULL`, `nullptr` via `uint64_t` |
| Floating point | `float`, `double`, `long double` |

Example:
```cpp
#include <windows.h>
#include <cstdio>
#include "main/RawlenString.hpp"

enum class MyEnum : int {
    first = 1,
    second = 2,
};

#define MY_CONST 42

int main() {
    for (;;) {
        printf("%s\n", (const char*)RS("hi"));
        Sleep(1000);

        printf("%s\n", (const char*)RS("Helllo!!!"));
        Sleep(1000);

        wprintf(L"%s\n", (const wchar_t*)RS(L"wide string"));
        Sleep(1000);

        printf("%d\n", (int)RV(555));
        Sleep(1000);

        printf("%d\n", (int)RV(MY_CONST));
        Sleep(1000);

        printf("%d %d\n", (int)RV(MyEnum::first), (int)RV(MyEnum::second));
        Sleep(1000);

        printf("%hhx\n", (int)RV((int8_t)0x12));
        Sleep(1000);

        printf("%hx\n", (int)RV((int16_t)0x1234));
        Sleep(1000);

        printf("%x\n", (int)RV(0x12345678));
        Sleep(1000);

        printf("%llx\n", (unsigned long long)RV(0x1234567887654321ull));
        Sleep(1000);

        printf("%u\n", (unsigned int)RV(4294967295u));
        Sleep(1000);

        printf("%p\n", (void*)RV((uint64_t)nullptr));
        Sleep(1000);

        printf("%f\n", RVF(1.0f));
        Sleep(1000);

        printf("%lf\n", RVF(2.71828));
        Sleep(1000);

        printf("%Lf\n", RVF(3.14159265358979L));
        Sleep(1000);

        printf("%s\n", (const char*)RS("\x61\x62\x63\x64"));
        Sleep(1000);

        printf("%s\n", (const char*)RS(R"(raw string)"));
        Sleep(1000);

        wprintf(L"%s\n", (const wchar_t*)RS(LR"(raw wstring)"));
        Sleep(1000);

        HMODULE hMod = GetModuleHandleA(RS("kernel32.dll"));
        printf("kernel32.dll handle: %p\n", (void*)hMod);
        Sleep(1000);

        FARPROC fn = GetProcAddress(hMod, RS("VirtualAlloc"));
        printf("VirtualAlloc addr: %p\n", (void*)fn);
        Sleep(1000);

        printf("---\n");
        Sleep(1000);
    }
    return 0;
}
```

---

# Proof
<img width="1109" height="629" alt="image" src="https://github.com/user-attachments/assets/c38d5f4d-51e4-463d-852e-d7aeefe5dde8" />

---

# Supported compilers
* MSVC (Visual Studio 2019+)

# Usage
> The most fundamental appeal:
```cpp
#include "main/RawlenString.hpp"
```

# RS stands for “strings”
```cpp
printf("%s\n", (const char*)RS("hello world"));
printf("%s\n", (const char*)RS("secret string?"));
wprintf(L"%s\n", (const wchar_t*)RS(L"wide string"));
```

# RV consists of integers and constants
```cpp
int value      = RV(1337);
DWORD pid      = RV(0xaaaaaaaa);
WORD  port     = RV(8080);
auto  myenum   = RV(MyEnum::first);
auto  ptr      = RV(nullptr);
```

# RVF is for various numbers
```cpp
float  f = RVF(3.14f);
double d = RVF(2.71828);
```

# A Discussion of Opaque Predicates
> The result is mathematically determined, but the compiler cannot determine it due to the truth logic, which is a prerequisite for graph embedding.
```cpp
// ALWAYS even: n*(n+1)
bool True1(uint64_t v) {
    volatile uint64_t a = v;
    volatile uint64_t b = v + 1;
    volatile uint64_t c = a * b;
    volatile uint64_t d = c & 1ull;
    return d == 0;
}
```

# Or let me give the example of the False operand:
```cpp
// Always false: x ^ x is always 0
bool False6(uint64_t v) {
    volatile uint64_t x = v ^ v;
    return x > 0;
}
```
> Similarly, in the case of `y < 10 || x * (x + 1) % 2 == 0)`, where the product of two consecutive numbers is always even, we construct predicates based on mathematically guaranteed properties, while remaining opaque to static analysis.

# Virtualized finite State machine

> Decoding is performed via a switch-dispatcher with more than 40 states, each of which can be valid and correct, and can exist outside the graph and the stack. Transitions are determined by opaque predicates:
```
0x1001 ──► 0x10A1 ──► 0x1002 ──► 0x10B2 ──► 0x1003 ──► ...
  │                                                        │
  └──► 0xAA01 ──► 0xAA0A ──► 0xAA02 ──► ... ──► 0x7F0F ◄─┘
```

> Each compilation produces a unique graph thanks to __TIME__, __DATE__, and __COUNTER__.

# Trampoline Dispatch
> Essentially, this is an indirect call an alternative to a direct call—a table of function pointers that prevents inlining and tracing:
```cpp
inline volatile TrampolineFn Table[8] = { J0, J1, J2, J3, J4, J5, J6, J7 };

uint64_t Dispatch(uint64_t v, uint64_t sel) {
    volatile auto fn = Table[sel & 7];
    return fn(v);
}
```
# Distant Islands
> Title of the hypothetical intermediary's work. Following the main thread, we have unreachable blocks containing alternative decryption implementations, protected by opaque predicates. These are never executed, but they generate fully functional machine code:
```cpp
if (Opaque::False1(final_chain)) goto str_island_1;
if (Opaque::False4(final_chain)) goto str_island_2;
// ...
return buf; // always here

str_island_1:
    Distant::DistantIsland1<Seed, CharT, N>(enc, buf.data);
    return buf;
```

## Limitations

| Limitation | Details |
|---|---|
| Input | String literals only, runtime variables are not supported |
| Compiler | MSVC only, relies on `__forceinline` and `__declspec(noinline)` |
| Compilation time | Noticeably longer than xorstr or oxorany due to complexity |

---

## Control Flow Graph Examples

### Initialization graph

<img width="592" height="980" alt="image" src="https://github.com/user-attachments/assets/d2f0ead4-8966-46a1-90cc-e0f989e30482" />

---

### Exit point initialization (partial view)

<img width="974" height="557" alt="image" src="https://github.com/user-attachments/assets/ce2348b9-74f5-4fe6-9445-8532ea77adb3" />

---

### Overview — the graphs are large

<img width="1037" height="574" alt="image" src="https://github.com/user-attachments/assets/37d8da79-7289-4e42-a533-f9e3949325b1" />

---

### Encrypted value graph

<img width="580" height="1005" alt="image" src="https://github.com/user-attachments/assets/b6432aec-0187-4ec1-98f8-ca346688000a" />

<img width="570" height="605" alt="image" src="https://github.com/user-attachments/assets/86b88b17-42a9-44e3-a251-db40dc3c75af" />

---

### RSP and SP violations visible in IDA

The stack pointer analysis is deliberately broken, preventing correctly resolving the stack frame.

<img width="522" height="234" alt="image" src="https://github.com/user-attachments/assets/b0128262-4c54-446b-8ec2-344dfaf589e2" />

---

### > Function too large to decompile

The generated function exceeds what IDA's decompiler can process, making F5 unavailable.

<img width="851" height="413" alt="image" src="https://github.com/user-attachments/assets/0a1a22cd-1103-46bf-8b25-9db8a0e4f9d2" />

# Overall, great for concealment.
