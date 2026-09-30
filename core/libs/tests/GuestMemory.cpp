#include "prx/libc/include/general/VabiMacros.hpp"
#include "prx/libc/include/GuestAllocations.hpp"
#include "prx/libc/include/GuestHeap.hpp"
#include "prx/libc/include/GuestArena.hpp"
#include <array>
#include "SceTypes.hpp"
#include <cstring>
#include <exception>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>

extern "C" {
void* APS5_VABI mmap_nid_postfix(void*, std::size_t, int, int, int, std::int64_t) noexcept;
int APS5_VABI munmap_nid_postfix(void*, std::size_t) noexcept;
int* APS5_VABI __error_nid_postfix();
int APS5_VABI sceKernelMapNamedFlexibleMemory(void**, std::size_t, int, int, const char*);
int APS5_VABI sceKernelMapFlexibleMemory(void**, std::size_t, int, int);
int APS5_VABI sceKernelMunmap(void*, std::size_t);
int APS5_VABI sceKernelVirtualQuery(const void*, int, VirtualQueryInfo*, std::uint64_t);
int APS5_VABI sceKernelSetVirtualRangeName(const void*, std::uint64_t, const char*);
int APS5_VABI sceKernelClearVirtualRangeName(const void*, std::uint64_t);
int APS5_VABI sceKernelAllocateDirectMemory(std::int64_t, std::int64_t, std::size_t, std::size_t, int, std::int64_t*);
int APS5_VABI sceKernelMapDirectMemory(void**, std::size_t, int, int, std::int64_t, std::size_t);
int APS5_VABI sceKernelMprotect(const void*, std::size_t, int);
int APS5_VABI sceKernelReleaseDirectMemory(std::int64_t, std::size_t);
int APS5_VABI sceKernelReserveVirtualRange(void**, std::size_t, int, std::size_t);
}

static void Require(bool condition) {
    if (!condition) {
        std::fputs("Guest memory check failed\n", stderr);
        std::abort();
    }
}

static const char* NameAt(const void* address) {
    static VirtualQueryInfo info;
    Require(sceKernelVirtualQuery(address, 0, &info, sizeof(info)) == 0);
    return info.name;
}

static void CheckNamedAndHintedMappings() {
    constexpr std::size_t length = 0x10000;
    void* first = nullptr;
    Require(sceKernelMapNamedFlexibleMemory(&first, length, 3, 0, "first mapping") == 0);
    Require(std::strcmp(NameAt(first), "first mapping") == 0);
    auto* middle = static_cast<unsigned char*>(first) + 0x4000;
    Require(sceKernelSetVirtualRangeName(middle, 0x4000, "middle") == 0);
    Require(std::strcmp(NameAt(first), "first mapping") == 0);
    Require(std::strcmp(NameAt(middle), "middle") == 0);
    Require(sceKernelClearVirtualRangeName(first, length) == 0);
    Require(NameAt(middle)[0] == '\0');
    Require(sceKernelSetVirtualRangeName(nullptr, length, "x") != 0);
#if defined(__linux__)
    void* hinted = first;
    Require(sceKernelMapFlexibleMemory(&hinted, length, 3, 0) == 0);
    Require(hinted > first && (reinterpret_cast<std::uintptr_t>(hinted) & 0x3fff) == 0);
    bool rejected = false;
    void* overwrite = first;
    try { sceKernelMapFlexibleMemory(&overwrite, 0x4000, 3, 0x90); } catch (const std::exception&) { rejected = true; }
    Require(rejected && overwrite == first);
    Require(sceKernelMunmap(hinted, length) == 0);
#endif
    Require(sceKernelMunmap(first, length) == 0);
}

static void CheckDirectMemoryFollowsPhysicalPages() {
    constexpr std::size_t page = 0x4000;
    std::int64_t phys = 0;
    Require(sceKernelAllocateDirectMemory(0, 0x7fffffffffll, page * 2, 0, 0, &phys) == 0);
    void* first = nullptr;
    Require(sceKernelMapDirectMemory(&first, page * 2, 3, 0, phys, 0) == 0);
    static_cast<unsigned char*>(first)[0] = 11;
    static_cast<unsigned char*>(first)[page + 5] = 22;
    void* alias = nullptr;
    Require(sceKernelMapDirectMemory(&alias, page, 3, 0, phys + page, 0) == 0);
    Require(alias != first && static_cast<unsigned char*>(alias)[5] == 22);
    static_cast<unsigned char*>(alias)[5] = 37;
    Require(static_cast<unsigned char*>(first)[page + 5] == 37);
    static_cast<unsigned char*>(first)[page + 6] = 48;
    Require(static_cast<unsigned char*>(alias)[6] == 48);
    Require(sceKernelMprotect(alias, page, 1) == 0);
    static_cast<unsigned char*>(first)[page + 5] = 59;
    Require(static_cast<unsigned char*>(alias)[5] == 59);
    Require(sceKernelMprotect(alias, page, 3) == 0);
    static_cast<unsigned char*>(alias)[5] = 22;
    Require(static_cast<unsigned char*>(first)[page + 5] == 22);
    Require(sceKernelMunmap(alias, page) == 0);
    static_cast<unsigned char*>(first)[page + 5] = 22;
    Require(sceKernelMunmap(first, page * 2) == 0);
    void* filler = nullptr;
    Require(sceKernelMapFlexibleMemory(&filler, page * 2, 3, 0) == 0);
    void* second = nullptr;
    Require(sceKernelMapDirectMemory(&second, page, 3, 0, phys + page, 0) == 0);
    Require(second != first && static_cast<unsigned char*>(second)[5] == 22);
    void* reserved = nullptr;
    Require(sceKernelReserveVirtualRange(&reserved, page, 0, 0) == 0);
    void* fixed = reserved;
    Require(sceKernelMapDirectMemory(&fixed, page, 1, 0x10, phys, 0) == 0);
    Require(fixed == reserved && static_cast<unsigned char*>(fixed)[0] == 11);
    Require(sceKernelMunmap(fixed, page) == 0);
    Require(sceKernelMunmap(second, page) == 0);
    Require(sceKernelReleaseDirectMemory(phys, page * 2) == 0);
    std::int64_t again = 0;
    Require(sceKernelAllocateDirectMemory(0, 0x7fffffffffll, page * 2, 0, 0, &again) == 0 && again == phys);
    void* fresh = nullptr;
    Require(sceKernelMapDirectMemory(&fresh, page * 2, 3, 0, again, 0) == 0);
    Require(static_cast<unsigned char*>(fresh)[0] == 0 && static_cast<unsigned char*>(fresh)[page + 5] == 0);
    Require(sceKernelMunmap(fresh, page * 2) == 0);
    Require(sceKernelMunmap(filler, page * 2) == 0);
    Require(sceKernelReleaseDirectMemory(again, page * 2) == 0);
}

static void CheckSharedDirectMemoryLifecycle() {
    constexpr std::size_t page = 0x4000;
    std::int64_t phys = 0;
    Require(sceKernelAllocateDirectMemory(0, 0x7fffffffffll, page * 3, 0, 0, &phys) == 0);
    void* first = nullptr;
    void* second = nullptr;
    Require(sceKernelMapDirectMemory(&first, page * 3, 3, 0, phys, 0) == 0);
    Require(sceKernelMapDirectMemory(&second, page * 3, 3, 0, phys, 0) == 0);
    VirtualQueryInfo info{};
    Require(sceKernelVirtualQuery(second, 0, &info, sizeof(info)) == 0);
    Require(info.is_direct && !info.is_flexible && info.offset == static_cast<std::uint64_t>(phys));
    auto* left = static_cast<unsigned char*>(first);
    auto* right = static_cast<unsigned char*>(second);
    left[0] = 31;
    right[page] = 47;
    left[page * 2] = 63;
    Require(right[0] == 31 && left[page] == 47 && right[page * 2] == 63);
    void* inaccessible = nullptr;
    Require(sceKernelMapDirectMemory(&inaccessible, page, 0, 0, phys + page, 0) == 0);
    left[page] = 48;
    Require(sceKernelMprotect(inaccessible, page, 1) == 0);
    Require(static_cast<const unsigned char*>(inaccessible)[0] == 48);
    Require(sceKernelMunmap(inaccessible, page) == 0);
    Require(sceKernelMunmap(left + page, page) == 0);
    right[page] = 79;
    Require(left[0] == 31 && left[page * 2] == 63);
    void* middle = left + page;
    Require(sceKernelMapDirectMemory(&middle, page, 3, 0x10, phys + page, 0) == 0);
    Require(left[page] == 79);
    Require(sceKernelVirtualQuery(middle, 0, &info, sizeof(info)) == 0);
    Require(info.offset == static_cast<std::uint64_t>(phys) + page && info.start == reinterpret_cast<std::uintptr_t>(middle));
    Require(sceKernelMprotect(second, page * 3, 0) == 0);
    left[page] = 95;
    Require(sceKernelMprotect(second, page * 3, 1) == 0);
    Require(right[page] == 95);
    Require(sceKernelMunmap(first, page) == 0);
    Require(sceKernelMunmap(left + page * 2, page) == 0);
    Require(sceKernelMunmap(middle, page) == 0);
    Require(sceKernelMprotect(second, page * 3, 3) == 0);
    right[page * 2] = 111;
    void* reserved = nullptr;
    Require(sceKernelReserveVirtualRange(&reserved, page * 3, 0, 0) == 0);
    void* fixed = static_cast<unsigned char*>(reserved) + page;
    Require(sceKernelMapDirectMemory(&fixed, page, 3, 0x10, phys + page * 2, 0) == 0);
    Require(static_cast<unsigned char*>(fixed)[0] == 111);
    static_cast<unsigned char*>(fixed)[0] = 127;
    Require(right[page * 2] == 127);
    Require(sceKernelMapFlexibleMemory(&fixed, page, 3, 0x10) == 0);
    Require(static_cast<unsigned char*>(fixed)[0] == 0);
    Require(sceKernelVirtualQuery(fixed, 0, &info, sizeof(info)) == 0);
    Require(!info.is_direct && info.is_flexible && info.offset == 0);
    static_cast<unsigned char*>(fixed)[0] = 143;
    Require(right[page * 2] == 127);
    Require(sceKernelMunmap(reserved, page * 3) == 0);
    Require(sceKernelMunmap(second, page * 3) == 0);
    Require(sceKernelReleaseDirectMemory(phys + page, page) == 0);
    std::int64_t replacement = 0;
    Require(sceKernelAllocateDirectMemory(phys + page, phys + page * 2, page, 0, 0, &replacement) == 0);
    Require(replacement == phys + page);
    void* mixed = nullptr;
    Require(sceKernelMapDirectMemory(&mixed, page * 3, 3, 0, phys, 0) == 0);
    const auto* data = static_cast<const unsigned char*>(mixed);
    Require(data[0] == 31 && data[page] == 0 && data[page * 2] == 127);
    Require(sceKernelMunmap(mixed, page * 3) == 0);
    Require(sceKernelReleaseDirectMemory(phys, page * 3) == 0);
}

static void CheckHeapAfterMappingReuse() {
    constexpr std::size_t bytes = 0x30000;
    auto* pointer = static_cast<unsigned char*>(GuestHeap::GuestHeapAllocate_nid_postfix(bytes));
    std::memset(pointer, 0x5a, bytes);
    Require(pointer[0] == 0x5a && pointer[bytes - 1] == 0x5a);
    GuestHeap::GuestHeapFree_nid_postfix(pointer);
    pointer = static_cast<unsigned char*>(GuestHeap::GuestHeapAllocate_nid_postfix(bytes));
    std::memset(pointer, 0xa5, bytes);
    Require(pointer[0] == 0xa5 && pointer[bytes - 1] == 0xa5);
    GuestHeap::GuestHeapFree_nid_postfix(pointer);
}

static void CheckSharedWriteTracking() {
#ifdef _WIN32
    constexpr std::size_t page = 0x4000;
    std::int64_t phys = 0;
    Require(sceKernelAllocateDirectMemory(0, 0x7fffffffffll, page * 3, 0, 0, &phys) == 0);
    void* first = nullptr;
    void* second = nullptr;
    Require(sceKernelMapDirectMemory(&first, page * 3, 3, 0, phys, 0) == 0);
    Require(sceKernelMapDirectMemory(&second, page * 3, 3, 0, phys, 0) == 0);
    const auto collect = [](void* address, std::size_t bytes, bool clear = true) {
        std::array<void*, 32> pages{};
        std::size_t count = pages.size();
        Require(GuestArena::GuestArenaCollectWrites_nid_postfix(reinterpret_cast<std::uintptr_t>(address), bytes, pages.data(), &count, clear));
        return count;
    };
    Require(collect(first, page * 3) == 12);
    Require(collect(second, page * 3) == 12);
    Require(collect(first, page * 3) == 0);
    Require(collect(second, page * 3) == 0);
    auto* left = static_cast<volatile unsigned char*>(first);
    auto* right = static_cast<volatile unsigned char*>(second);
    left[page + 5] = 21;
    Require(right[page + 5] == 21);
    Require(collect(first, page * 3, false) == 4);
    Require(collect(first, page * 3, false) == 4);
    Require(collect(first, page * 3) == 4);
    Require(collect(second, page * 3) == 4);
    Require(collect(first, page * 3) == 0);
    right[page * 2] = 42;
    Require(collect(first, page * 3) == 4);
    Require(collect(second, page * 3) == 4);
    Require(collect(second, page * 3) == 0);
    Require(sceKernelMprotect(first, page * 3, 1) == 0);
    collect(first, page * 3);
    collect(second, page * 3);
    right[0] = 63;
    Require(left[0] == 63 && collect(first, page * 3) == 4);
    Require(sceKernelMprotect(first, page * 3, 3) == 0);
    collect(first, page * 3);
    left[0] = 84;
    Require(right[0] == 84 && collect(second, page * 3) != 0);
    void* third = nullptr;
    Require(sceKernelMapDirectMemory(&third, page, 3, 0, phys + page, 0) == 0);
    collect(first, page * 3);
    collect(second, page * 3);
    static_cast<volatile unsigned char*>(third)[0] = 105;
    Require(collect(first, page * 3) == 4 && collect(second, page * 3) == 4);
    Require(sceKernelMunmap(third, page) == 0);
    Require(sceKernelMunmap(first, page * 3) == 0);
    Require(sceKernelMunmap(second, page * 3) == 0);
    Require(sceKernelReleaseDirectMemory(phys, page * 3) == 0);
#endif
}

int main() {
    CheckNamedAndHintedMappings();
    CheckDirectMemoryFollowsPhysicalPages();
    CheckSharedDirectMemoryLifecycle();
    CheckHeapAfterMappingReuse();
    CheckSharedWriteTracking();
    constexpr std::size_t page = 0x4000;
    const auto failed = reinterpret_cast<void*>(static_cast<std::uintptr_t>(-1));
    const auto reject = [&](std::size_t length, int protection, int flags, int fd,
                            std::int64_t offset, int error) {
        *__error_nid_postfix() = 0;
        Require(mmap_nid_postfix(nullptr, length, protection, flags, fd, offset) == failed);
        Require(*__error_nid_postfix() == error);
    };
    reject(0, 3, 0x1002, -1, 0, 22);
    reject(std::numeric_limits<std::size_t>::max(), 3, 0x1002, -1, 0, 22);
    reject(page, 8, 0x1002, -1, 0, 22);
    reject(page, 3, 0x1002, 0, 0, 22);
    reject(page, 3, 0x1002, -1, 1, 22);
    reject(page, 3, 0x1001, -1, 0, 45); // shared
    reject(page, 3, 0x1012, -1, 0, 45); // fixed
    reject(page, 3, 0x2, 0, 0, 45);    // file-backed
    reject(page, 3, 0x22, -1, 0, 45);  // Linux MAP_ANON is not guest MAP_ANON

    auto* memory = static_cast<unsigned char*>(mmap_nid_postfix(nullptr, page * 3 - 1, 3, 0x1002, -1, 0));
    Require(memory != failed && (reinterpret_cast<std::uintptr_t>(memory) & (page - 1)) == 0);
    for (std::size_t i = 0; i < page * 3; ++i) Require(memory[i] == 0);
    memory[0] = 42;
    memory[page * 2] = 73;
    {
        GuestAllocations::Mutation mutation;
        const auto range = mutation.Find(memory);
        Require(range.bytes == page * 3 && range.readable && range.writable);
    }
    Require(munmap_nid_postfix(memory + 1, page) == -1 && *__error_nid_postfix() == 22);
    Require(munmap_nid_postfix(memory, 0) == -1 && *__error_nid_postfix() == 22);
    Require(memory[0] == 42);
    Require(munmap_nid_postfix(memory + page, 1) == 0); // round to one guest page
    Require(memory[0] == 42 && memory[page * 2] == 73);
    Require(munmap_nid_postfix(memory, page) == 0);
    Require(memory[page * 2] == 73);
    Require(munmap_nid_postfix(memory + page * 2, page) == 0);
    Require(munmap_nid_postfix(memory, page) == -1);
    for (int protection : {0, 1, 3, 5}) {
        void* mapped = mmap_nid_postfix(memory, 1, protection, 0x1002, -1, 0);
        Require(mapped != failed);
        {
            GuestAllocations::Mutation mutation;
            const auto range = mutation.Find(mapped);
            Require(range.readable == ((protection & 3) != 0));
            Require(range.writable == ((protection & 2) != 0));
        }
        Require(munmap_nid_postfix(mapped, 1) == 0);
    }
}
