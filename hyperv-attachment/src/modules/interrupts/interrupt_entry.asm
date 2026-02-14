extern ?process_nmi@interrupts@@YAXPEAUcontext_t@1@@Z : proc
extern g_interrupts_ctx_ptr : qword
extern original_nmi_handler : qword

.code
	save_general_purpose_regisers macro
		mov [rsp], rax
		mov [rsp+8], rcx
		mov [rsp+16], rdx
		mov [rsp+24], rbx
		mov [rsp+32], rbp
		mov [rsp+40], rsi
		mov [rsp+48], rdi
		mov [rsp+56], r8
		mov [rsp+64], r9
		mov [rsp+72], r10
		mov [rsp+80], r11
		mov [rsp+88], r12
		mov [rsp+96], r13
		mov [rsp+104], r14
		mov [rsp+112], r15
	endm

	restore_general_purpose_regisers macro
		mov rax, [rsp]
		mov rcx, [rsp+8]
		mov rdx, [rsp+16]
		mov rbx, [rsp+24]
		mov rbp, [rsp+32]
		mov rsi, [rsp+40]
		mov rdi, [rsp+48]
		mov r8, [rsp+56]
		mov r9, [rsp+64]
		mov r10, [rsp+72]
		mov r11, [rsp+80]
		mov r12, [rsp+88]
		mov r13, [rsp+96]
		mov r14, [rsp+104]
		mov r15, [rsp+112]
	endm

	save_xmm_registers macro
		movdqu [rsp], xmm0
		movdqu [rsp+16], xmm1
		movdqu [rsp+32], xmm2
		movdqu [rsp+48], xmm3
		movdqu [rsp+64], xmm4
		movdqu [rsp+80], xmm5
		movdqu [rsp+96], xmm6
		movdqu [rsp+112], xmm7
		movdqu [rsp+128], xmm8
		movdqu [rsp+144], xmm9
		movdqu [rsp+160], xmm10
		movdqu [rsp+176], xmm11
		movdqu [rsp+192], xmm12
		movdqu [rsp+208], xmm13
		movdqu [rsp+224], xmm14
		movdqu [rsp+240], xmm15
	endm

	restore_xmm_registers macro
		movdqu xmm15, [rsp+240]
		movdqu xmm14, [rsp+224]
		movdqu xmm13, [rsp+208]
		movdqu xmm12, [rsp+192]
		movdqu xmm11, [rsp+176]
		movdqu xmm10, [rsp+160]
		movdqu xmm9, [rsp+144]
		movdqu xmm8, [rsp+128]
		movdqu xmm7, [rsp+112]
		movdqu xmm6, [rsp+96]
		movdqu xmm5, [rsp+80]
		movdqu xmm4, [rsp+64]
		movdqu xmm3, [rsp+48]
		movdqu xmm2, [rsp+32]
		movdqu xmm1, [rsp+16]
		movdqu xmm0, [rsp]
	endm

	handle_nmi macro
		sub rsp, 78h
		save_general_purpose_regisers

		sub rsp, 100h
		save_xmm_registers

		sub rsp, 20h
		mov rcx, qword ptr [g_interrupts_ctx_ptr]
		call ?process_nmi@interrupts@@YAXPEAUcontext_t@1@@Z
		add rsp, 20h

		restore_xmm_registers
		add rsp, 100h

		restore_general_purpose_regisers
		add rsp, 78h
	endm

	nmi_standalone_entry proc
		handle_nmi

		iretq
	nmi_standalone_entry endp

	nmi_entry proc
		handle_nmi

		jmp original_nmi_handler
	nmi_entry endp
END
