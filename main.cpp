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