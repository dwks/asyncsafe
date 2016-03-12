.global asyncsafe_violation_asm
.extern asyncsafe_violation
.extern plt_allowed
.extern orig_resolve

# first PLT entry
#  ff 35 02 06 20 00     pushq  0x200602(%rip)        # 0x600a68
#  ff 25 04 06 20 00     jmpq   *0x200604(%rip)        # 0x600a70
#  0f 1f 40 00           nopl   0x0(%rax)
# normal PLT entry
#  <raise@plt+0>:   ff 25 02 06 20 00  jmpq   *0x200602(%rip)        # 0x600a78
#  <raise@plt+6>:   68 00 00 00 00     pushq  $0x0
#  <raise@plt+11>:  e9 e0 ff ff ff     jmpq   0x400460

asyncsafe_violation_asm:
    # at rsp is the got reference
    mov     8(%rsp), %r10
    mov     plt_allowed@gotpcrel(%rip), %r11
    cmp     $0, (%r11, %r10, 4)
    jnz     .good
    push    %rdi
    mov     %r10, %rdi
    call    asyncsafe_violation@plt
    pop     %rdi
.good:
    mov     orig_resolve@gotpcrel(%rip), %r11
    jmp     *(%r11)

