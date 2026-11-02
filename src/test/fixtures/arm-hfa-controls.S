.syntax unified
.arm
.fpu vfpv3-d16
.text
.global hfa_control
.type hfa_control,%function
hfa_control:
    .cfi_startproc
    push {fp}
    .cfi_def_cfa_offset 4
    .cfi_offset 11,-4
    add fp,sp,#0
    .cfi_def_cfa_register 11
    sub sp,sp,#12
#if FORGE_CORE_STORAGE
    vmov s14,r0
    vmov s15,r1
#else
    vmov.f32 s14,s0
    vmov.f32 s15,s1
#endif
    vstr s14,[fp,#-12]
    vstr s15,[fp,#-8]
    vldr s14,[fp,#-12]
#if FORGE_CORE_STORAGE
#if FORGE_HFA_CONTROL == 4
    str r3,[fp,#-8]
#elif FORGE_HFA_CONTROL == 5
    str r3,[fp,#-4]
#elif FORGE_HFA_CONTROL == 6
    str r3,[r2]
#else
    vldr s15,[fp,#-8]
#endif
#else
#if FORGE_HFA_CONTROL == 4
    str r1,[fp,#-8]
#elif FORGE_HFA_CONTROL == 5
    str r1,[fp,#-4]
#elif FORGE_HFA_CONTROL == 6
    str r1,[r0]
#else
    vldr s15,[fp,#-8]
#endif
#endif
    vadd.f32 s15,s14,s15
#if FORGE_CORE_STORAGE
#if FORGE_HFA_CONTROL == 0
    vmov r0,s15
#elif FORGE_HFA_CONTROL == 1
    vmov r12,s15
#elif FORGE_HFA_CONTROL == 3
    vmov r0,r1,d7
#else
    vmov r1,s15
#endif
#else
#if FORGE_HFA_CONTROL == 0
    vmov.f32 s0,s15
#elif FORGE_HFA_CONTROL == 1
    vmov.f32 s2,s15
#elif FORGE_HFA_CONTROL == 3
    vmov.f64 d0,d7
#else
    vmov.f32 s1,s15
#endif
#endif
    add sp,fp,#0
    pop {fp}
    .cfi_def_cfa_register 13
    .cfi_def_cfa_offset 0
    .cfi_restore 11
    bx lr
    .cfi_endproc
.size hfa_control,.-hfa_control

.global hfa_alias
.type hfa_alias,%function
hfa_alias:
    .cfi_startproc
#if FORGE_CORE_STORAGE
    sub r2,sp,#12
#else
    sub r0,sp,#12
#endif
    b hfa_control
    .cfi_endproc
.size hfa_alias,.-hfa_alias
.section .note.GNU-stack,"",%progbits
