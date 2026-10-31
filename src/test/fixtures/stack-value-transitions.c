/* Physical compiler locals expose spill/reload and slot reuse without mutating
 * the incoming C argument's logical identity. */
#if defined(__x86_64__)
#define FIRST "r10"
#define SECOND "r11"
#define ORIGINAL "rdi"
#define ORIGINAL_KILL "xorl %%edi, %%edi\n"
#define LOAD32 "movl %[slot], %k[first]\n"
#define LOAD64 "movq %[slot], %[first]\n"
#define SAVE32 "movl %k[first], %[slot2]\n"
#define SAVE64 "movq %[first], %[slot2]\n"
#define AGAIN32 "movl %[slot2], %k[second]\n"
#define AGAIN64 "movq %[slot2], %[second]\n"
#define ZERO32 "movl $0, %[slot]\n"
#define ZERO64 "movq $0, %[slot]\n"
#define ZERO_SECOND32 "movl $0, %[slot2]\n"
#define ZERO_SECOND64 "movq $0, %[slot2]\n"
#define ALIAS32 "movl $0, (%[alias])\n"
#define ALIAS64 "movq $0, (%[alias])\n"
#define FIRST_KILL "xorl %%r10d, %%r10d\n"
#define SECOND_KILL "xorl %%r11d, %%r11d\n"
#elif defined(__aarch64__)
#define FIRST "x9"
#define SECOND "x10"
#define ORIGINAL "x0"
#define ORIGINAL_KILL "mov x0, xzr\n"
#define LOAD32 "ldr %w[first], %[slot]\n"
#define LOAD64 "ldr %x[first], %[slot]\n"
#define SAVE32 "str %w[first], %[slot2]\n"
#define SAVE64 "str %x[first], %[slot2]\n"
#define AGAIN32 "ldr %w[second], %[slot2]\n"
#define AGAIN64 "ldr %x[second], %[slot2]\n"
#define ZERO32 "str wzr, %[slot]\n"
#define ZERO64 "str xzr, %[slot]\n"
#define ZERO_SECOND32 "str wzr, %[slot2]\n"
#define ZERO_SECOND64 "str xzr, %[slot2]\n"
#define ALIAS32 "str wzr, [%[alias]]\n"
#define ALIAS64 "str xzr, [%[alias]]\n"
#define FIRST_KILL "mov w9, wzr\n"
#define SECOND_KILL "mov w10, wzr\n"
#else
#error Unsupported stack-transfer runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"
#define RELOAD(name, op_load) LABEL(name, reload) op_load LABEL(name, ready) "nop\n"
#define REUSE(name, op_zero) LABEL(name, reuse) op_zero LABEL(name, reused) "nop\n"
#define LOST(name) LABEL(name, kill_first) FIRST_KILL LABEL(name, first_lost) "nop\n"
#define KEEP(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    RELOAD(name, op_load) REUSE(name, op_zero)
#define LOSS(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    KEEP(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) LOST(name)
#define BADLOAD(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    REUSE(name, op_zero) RELOAD(name, op_load)
#define ALIAS(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    LABEL(name, alias_write) op_alias LABEL(name, aliased) "nop\n" RELOAD(name, op_load)
#define RESPILL(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    RELOAD(name, op_load) LABEL(name, save_again) op_save LABEL(name, saved_again) "nop\n" \
    REUSE(name, op_zero) LOST(name) LABEL(name, reload_again) op_again LABEL(name, ready_again) "nop\n" \
    LABEL(name, reuse_again) op_zero2 LABEL(name, reused_again) "nop\n"
#define CHAINLOSS(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    RESPILL(name, op_load, op_save, op_again, op_zero, op_zero2, op_alias) \
    LABEL(name, kill_second) SECOND_KILL LABEL(name, second_lost) "nop\n"
#define FUNCTION(type, name, shape, load, save, again, zero, zero2, alias_store, result) \
    __attribute__((noinline, noclone)) type name(type input, volatile type *alias) { \
        volatile type slot2 = -3456; \
        volatile type slot = input; \
        register type first __asm__(FIRST) = -12345; \
        register type second __asm__(SECOND) = -23456; \
        __asm__ volatile(LABEL(name, before) "nop\n" LABEL(name, original_kill) ORIGINAL_KILL \
            LABEL(name, original_lost) "nop\n" shape(name, load, save, again, zero, zero2, alias_store) LABEL(name, finish) "nop\n" \
            : [first] "+&r"(first), [second] "+&r"(second), [slot] "+m"(slot), [slot2] "+m"(slot2) \
            : [alias] "r"(alias) : ORIGINAL, "cc", "memory"); \
        return result; \
    }
FUNCTION(int, transfer_keep32, KEEP, LOAD32, SAVE32, AGAIN32, ZERO32, ZERO_SECOND32, ALIAS32, first)
FUNCTION(long long, transfer_keep64, KEEP, LOAD64, SAVE64, AGAIN64, ZERO64, ZERO_SECOND64, ALIAS64, first)
FUNCTION(int, transfer_respill32, RESPILL, LOAD32, SAVE32, AGAIN32, ZERO32, ZERO_SECOND32, ALIAS32, second)
FUNCTION(long long, transfer_respill64, RESPILL, LOAD64, SAVE64, AGAIN64, ZERO64, ZERO_SECOND64, ALIAS64, second)
FUNCTION(int, transfer_loss32, LOSS, LOAD32, SAVE32, AGAIN32, ZERO32, ZERO_SECOND32, ALIAS32, first)
FUNCTION(long long, transfer_loss64, LOSS, LOAD64, SAVE64, AGAIN64, ZERO64, ZERO_SECOND64, ALIAS64, first)
FUNCTION(int, transfer_badload32, BADLOAD, LOAD32, SAVE32, AGAIN32, ZERO32, ZERO_SECOND32, ALIAS32, first)
FUNCTION(long long, transfer_badload64, BADLOAD, LOAD64, SAVE64, AGAIN64, ZERO64, ZERO_SECOND64, ALIAS64, first)
FUNCTION(int, transfer_alias32, ALIAS, LOAD32, SAVE32, AGAIN32, ZERO32, ZERO_SECOND32, ALIAS32, first)
FUNCTION(long long, transfer_alias64, ALIAS, LOAD64, SAVE64, AGAIN64, ZERO64, ZERO_SECOND64, ALIAS64, first)
FUNCTION(int, transfer_chainloss32, CHAINLOSS, LOAD32, SAVE32, AGAIN32, ZERO32, ZERO_SECOND32, ALIAS32, second)
FUNCTION(long long, transfer_chainloss64, CHAINLOSS, LOAD64, SAVE64, AGAIN64, ZERO64, ZERO_SECOND64, ALIAS64, second)
volatile int alias32;
volatile long long alias64;
#define CHECK(name, value, alias, expected) if (name(value, &(alias)) != (expected)) return 1;
__attribute__((noinline, noclone)) static int round_values(int small, long long large) {
    CHECK(transfer_keep32, small, alias32, small)
    CHECK(transfer_keep64, large, alias64, large)
    CHECK(transfer_respill32, small, alias32, small)
    CHECK(transfer_respill64, large, alias64, large)
    CHECK(transfer_loss32, small, alias32, 0)
    CHECK(transfer_loss64, large, alias64, 0)
    CHECK(transfer_badload32, small, alias32, 0)
    CHECK(transfer_badload64, large, alias64, 0)
    CHECK(transfer_alias32, small, alias32, small)
    CHECK(transfer_alias64, large, alias64, large)
    CHECK(transfer_chainloss32, small, alias32, 0)
    CHECK(transfer_chainloss64, large, alias64, 0)
    return 0;
}
int main(void) {
    return round_values(19, 19LL) || round_values(-19, -19LL) ||
        round_values(-1985229329, -81985529216486895LL);
}
