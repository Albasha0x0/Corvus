// Code in the form an ahead-of-time translator generates: objects with a
// class pointer, a vtable of {method pointer, method info} entries called by
// slot, a class-init flag, a lazy metadata-init flag, a null check that
// branches to a no-return throw helper, and an inlined write barrier.
#if defined(_MSC_VER)
#include <intrin.h>
#define EXPORT extern "C" __declspec(dllexport)
#define KEEP __declspec(noinline)
#define NORETURN __declspec(noreturn)
#define FENCE() __faststorefence()
#define TRAP() __debugbreak()
#define CAS(p, desired, expected) _InterlockedCompareExchange64((volatile long long*)(p), (long long)(desired), (long long)(expected))
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#define KEEP __attribute__((noinline))
#define NORETURN __attribute__((noreturn))
#define FENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define TRAP() __builtin_trap()
#define CAS(p, desired, expected) __sync_val_compare_and_swap((volatile long long*)(p), (long long)(expected), (long long)(desired))
#endif

struct Class;
struct Object { Class* klass; void* monitor; Object* next; };
typedef int (*Method)(Object*);
struct Slot { Method method; void* info; };
struct Class
{
    unsigned char header[0xE4];
    unsigned char initialized;
    unsigned char pad[0x138 - 0xE5];
    Slot vtable[16];
};

volatile unsigned char g_lazyOne, g_lazyTwo;
volatile unsigned long long g_cards[1024];
volatile int g_sink;

// Runtime support, reached through exported entry points and direct calls.
KEEP void InitMetadataImpl(int token) { g_sink = token; }
KEEP void ClassInitImpl(Class* c) { c->initialized = 1; g_sink = 7; }
KEEP void ClassSetupImpl(Class* c) { g_sink = (int)(c->header[0]); }
KEEP NORETURN void RaiseImpl(Object* e) { g_sink = e->klass != 0; TRAP(); for (;;) {} }
KEEP Object* MakeNullReference(void* storage) { Object* e = (Object*)storage; e->klass = 0; e->next = 0; return e; }
KEEP NORETURN void ThrowWrapper() { char storage[48]; RaiseImpl(MakeNullReference(storage)); }
KEEP NORETURN void ThrowNullReference() { ThrowWrapper(); }

EXPORT void il2cpp_raise_exception(Object* e) { RaiseImpl(e); }
EXPORT void il2cpp_runtime_class_init(Class* c) { ClassInitImpl(c); }

// One init call behind a flag.
EXPORT int M_LazyOne(Object* self, int x)
{
    if (!g_lazyOne) { InitMetadataImpl(0x101); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    return x + (int)(unsigned long long)self->klass;
}

// Two init calls with a fence before the flag store.
EXPORT int M_LazyTwo(Object* self, int x)
{
    if (!g_lazyTwo) { InitMetadataImpl(0x201); InitMetadataImpl(0x202); FENCE(); g_lazyTwo = 1; }
    if (!self) ThrowNullReference();
    return x * (int)(unsigned long long)self->monitor;
}

// Class-init flag checked before a static access, then a memory-form slot call.
EXPORT int M_SlotMemory(Object* self)
{
    if (!g_lazyOne) { InitMetadataImpl(0x301); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    Class* c = self->klass;
    if (!c->initialized) ClassInitImpl(c);
    int r = c->vtable[3].method(self);
    g_sink = r;
    return r;
}

// The slot entry is checked before the call, which leaves a register-form call.
EXPORT int M_SlotRegister(Object* self)
{
    if (!g_lazyOne) { InitMetadataImpl(0x401); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    Method m = self->klass->vtable[5].method;
    if (!m) return -1;
    return m(self) + 1;
}

// The call is the last action, so the compiler may emit a jump.
EXPORT int M_SlotTail(Object* self)
{
    if (!g_lazyOne) { InitMetadataImpl(0x801); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    return self->klass->vtable[3].method(self);
}

// A class-setup call with the class pointer, then a call through the reloaded pointer.
EXPORT int M_Setup(Object* self)
{
    if (!g_lazyOne) { InitMetadataImpl(0x501); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    ClassSetupImpl(self->klass);
    int r = self->klass->vtable[3].method(self);
    g_sink = r;
    return r;
}

EXPORT int M_SetupB(Object* self, int x)
{
    if (!g_lazyOne) { InitMetadataImpl(0x511); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    ClassSetupImpl(self->klass);
    int r = self->klass->vtable[3].method(self) + x;
    g_sink = r;
    return r * 2;
}

EXPORT int M_SetupC(Object* self, int x)
{
    if (!g_lazyOne) { InitMetadataImpl(0x521); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    ClassSetupImpl(self->klass);
    int r = self->klass->vtable[3].method(self) - x;
    g_sink = r;
    return r ^ 5;
}

// A reference store followed by the inlined card-table update.
EXPORT void M_Store(Object* self, Object* value)
{
    if (!g_lazyOne) { InitMetadataImpl(0x601); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    self->next = value;
    unsigned long long page = (unsigned long long)&self->next >> 12;
    volatile unsigned long long* word = &g_cards[(page >> 6) & 0x3FF];
    unsigned long long bit = 1ull << (page & 63);
    unsigned long long old = *word;
    while (CAS(word, old | bit, old) != (long long)old)
        old = *word;
}

// A second store function with a different body and the same barrier shape.
EXPORT void M_StoreTwo(Object* self, Object* value, int tag)
{
    if (!g_lazyOne) { InitMetadataImpl(0x701); g_lazyOne = 1; }
    if (!self) ThrowNullReference();
    g_sink = tag * 3;
    self->next = value;
    unsigned long long page = (unsigned long long)&self->next >> 12;
    volatile unsigned long long* word = &g_cards[(page >> 6) & 0x3FF];
    unsigned long long bit = 1ull << (page & 63);
    unsigned long long old = *word;
    while (CAS(word, old | bit, old) != (long long)old)
        old = *word;
}

// The same checks with other work scheduled between the test and the branch,
// and with values kept live across them.
EXPORT int M_LazyMoved(Object* self, int x, int y)
{
    int a = x * 7 + y;
    int b = y * 3 - x;
    if (!g_lazyTwo) { InitMetadataImpl(a); g_lazyTwo = 1; }
    return a * b + (int)(unsigned long long)self->klass;
}

EXPORT int M_ClassInitMoved(Object* self, int x)
{
    Class* c = self->klass;
    int a = x * 5;
    g_sink = a;
    if (!c->initialized) ClassInitImpl(c);
    return c->vtable[3].method(self) + a;
}

EXPORT void M_StoreMoved(Object* self, Object* value, int tag)
{
    self->next = value;
    unsigned long long page = (unsigned long long)&self->next >> 12;
    int work = tag * 5;
    volatile unsigned long long* word = &g_cards[(page >> 6) & 0x3FF];
    g_sink = work;
    unsigned long long bit = 1ull << (page & 63);
    unsigned long long old = *word;
    while (CAS(word, old | bit, old) != (long long)old)
        old = *word;
}
