#include "../app/src/main/cpp/arm64.h"
#include "../app/src/main/cpp/a64asm.h"
#include "../app/src/main/cpp/a64demo.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char outbuf[4096]; static size_t outn;
static void sink(void *ud, const char *b, size_t n) { (void)ud; memcpy(outbuf + outn, b, n); outn += n; outbuf[outn] = 0; }
static uint64_t test_impl(void *ud, unsigned key, bool write, uint64_t val) {
    uint64_t *r = ud; unsigned idx = (key & 7) + (((key >> 4) & 1) << 3);
    if (write) r[idx] = val;
    return r[idx];
}
static int fails;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("ok:   %s\n", msg); } while (0)

int main(void) {
    static uint8_t mem[0x10000]; A64 c;

    /* 1. full demo */
    a64_init(&c, mem, 0, sizeof mem); c.out = sink; outn = 0; outbuf[0] = 0;
    a64_demo_load(&c);
    int rc = a64_run(&c, 1000000);
    printf("--- demo output ---\n%s--- rc=%d steps=%llu ---\n", outbuf, rc, (unsigned long long)c.steps);
    CHECK(rc == 0 && c.exit_code == 0, "demo exits cleanly via svc #0x80");
    CHECK(strstr(outbuf, "sum(1..100) = 5050\n") != NULL, "loop + udiv/msub decimal print = 5050");
    CHECK(strstr(outbuf, "= 3628800\n") != NULL, "recursive factorial 10! = 3628800");

    /* 2. flags / 32-bit wrap: w0 = 0xFFFFFFFF; w0 += 1 -> 0 ; cmp -> Z */
    static Asm a; memset(&a, 0, sizeof a);
    a_movz(&a, 0, 0xFFFF); a_movk(&a, 0, 0xFFFF, 1);       /* x0 = 0xFFFFFFFF */
    a_e(&a, 0x11000400u);                                  /* add w0, w0, #1 */
    a_e(&a, 0x7100001Fu);                                  /* cmp w0, #0 */
    a_movz(&a, 8, 93); a_svc(&a, 0); a_finish(&a);
    a64_init(&c, mem, 0, sizeof mem); memset(mem, 0, sizeof mem);
    memcpy(mem + 0x1000, a.w, a.n * 4); c.pc = 0x1000;
    rc = a64_run(&c, 100);
    CHECK(rc == 0 && c.x[0] == 0 && c.z, "32-bit add wraps to 0 and sets Z");

    /* 3. fault on bad memory */
    memset(&a, 0, sizeof a);
    a_movz(&a, 1, 0xFFFF); a_movk(&a, 1, 0xFFFF, 1); a_ldr(&a, 0, 1, 0); a_finish(&a);
    a64_init(&c, mem, 0, sizeof mem); memset(mem, 0, sizeof mem);
    memcpy(mem + 0x1000, a.w, a.n * 4); c.pc = 0x1000;
    rc = a64_run(&c, 100);
    CHECK(rc == -1 && c.fault, "load from unmapped address faults");

    /* 4. step limit on infinite loop (b .) */
    memset(&a, 0, sizeof a); a_label(&a, 0); a_b(&a, 0); a_finish(&a);
    a64_init(&c, mem, 0, sizeof mem); memset(mem, 0, sizeof mem);
    memcpy(mem + 0x1000, a.w, a.n * 4); c.pc = 0x1000;
    CHECK(a64_run(&c, 1000) == 1, "infinite loop stops at step limit");

    /* 5. MODELLED Apple Guarded Execution Mode: genter (0x00201420) / SP_GL1 / gexit (0x00201400) */
    {
        uint64_t iregs[16] = {0};
        a64_init(&c, mem, 0, sizeof mem); memset(mem, 0, sizeof mem);
        c.stub_impl_regs = true; c.el = 1; c.spsel = 1;
        c.on_impl_reg = test_impl; c.impl_ud = iregs;
        c.sp = 0x4000; c.sp_bank[1] = 0x4000; /* SP_EL1 */
        c.sp_bank[2] = 0x8000; /* SP_GL1 */
        /* Pre-populate GXF_ENTRY_EL1 (S3_6_C15_C8_1) = 0x2000 via MSR at 0x1000 */
        uint32_t code1[] = {
            0xD2840000u, /* mov x0, #0x2000 */
            0xD51EF820u, /* msr S3_6_C15_C8_1, x0 */
            0x00201420u, /* genter #0 -> jumps to 0x2000, ELR_GL1=0x100c, gxf_mode=true */
            0xD2800AA2u, /* 0x100c: mov x2, #0x55 (reached after gexit) */
            0xD2800BA8u, /* mov x8, #93 */
            0xD4000001u, /* svc #0 */
        };
        uint32_t code2[] = {
            0x910003E1u, /* 0x2000: mov x1, sp (reads SP_GL1 = 0x8000) */
            0x910043FFu, /* add sp, sp, #16 (SP_GL1 -> 0x8010) */
            0x00201400u, /* gexit -> returns to ELR_GL1 (0x100c), gxf_mode=false */
        };
        memcpy(mem + 0x1000, code1, sizeof code1);
        memcpy(mem + 0x2000, code2, sizeof code2);
        c.pc = 0x1000;
        rc = a64_run(&c, 50);
        CHECK(rc == 0 && !c.gxf_mode && c.x[1] == 0x8000 && c.sp_bank[2] == 0x8010 && c.sp == 0x4000 && c.x[2] == 0x55,
              "Apple Guarded Execution Mode (genter/SP_GL1/gexit) round-trip");
    }

    printf(fails ? "\n%d FAILED\n" : "\nALL PASSED\n", fails);
    return fails != 0;
}
