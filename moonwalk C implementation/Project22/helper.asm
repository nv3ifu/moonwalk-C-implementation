; x64 assembly for MSVC (MASM)
.code

; Get Thread Environment Block (TEB) from GS:[0x30]
get_teb PROC
    mov rax, gs:[30h]
    ret
get_teb ENDP

; Get stack base from TEB + 0x08
get_stack_base PROC
    mov rax, gs:[30h]
    mov rax, [rax + 8h]
    ret
get_stack_base ENDP

; Get stack limit from TEB + 0x10
get_stack_limit PROC
    mov rax, gs:[30h]
    mov rax, [rax + 10h]
    ret
get_stack_limit ENDP

; Get current RSP
get_rsp PROC
    mov rax, rsp
    ret
get_rsp ENDP

END