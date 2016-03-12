.global asyncsafe_resolve_asm
.extern asyncsafe_violation
.extern plt_allowed
.extern orig_resolve

asyncsafe_resolve_asm:
    # at rsp+0 is the got reference
    mov     8(%rsp), %r10  # rsp+8 is the plt index
    mov     plt_allowed@gotpcrel(%rip), %r11
    mov     (%r11), %r11
    cmpb    $0, (%r11, %r10, 1)
    jnz     .good
    push    %rdi
    mov     %r10, %rdi
    call    asyncsafe_violation@plt
    pop     %rdi
.good:
    mov     orig_resolve@gotpcrel(%rip), %r11
    jmp     *(%r11)

