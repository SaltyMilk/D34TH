
global _start

_start:
	mov rax, 0x000000000000000a
	push rax
	mov rax, 0x656e616966756f53 ; Soufiane
	push rax
	mov rdi, rsp; store base str
	call ft_strlen
	mov r10, rax; store size

	mov rax, 0x0000000066756f53 ; Souf
	push rax
	mov rsi, rsp

	mov rax, 0x0000000068706f53 ; Soph
	push rax
	mov rdx, rsp

	call ft_str_replace
	call ft_puts

	add rsp, 24
	
	mov	rax, 0x3c;
	mov rdi, 0
	syscall; exit(0)
retn

;Replaces each occurence of 'to_replace' by 'with' in 'base_str'
;void ft_str_replace(char *base_str, char *to_replace, char *with, size_t size_base)
;                          rdi     ,       rsi       ,       rdx ,        r10
ft_str_replace:
	; calc to_replace length
	push rdi
	mov rdi, rsi
	call ft_strlen
	mov rcx, rax; rcx = strlen(to_replace)
	pop rdi
	
	xor rax, rax; int i = 0 

	fsr_loop:
	;check if we're at the end
	cmp rax, r10
	je fsr_loop_exit ; we reached end of base

	xor rbx, rbx; int j = 0;
	fsr_inloop: ; let's check if we can find the str to_replace
	mov r11b, [rsi + rbx]
	cmp r11b, 0
	jne fsr_inloop_cont
	;if we reach this than it's time to replace
	xor rbx, rbx
	fsr_replace_loop:
	cmp byte[rdx + rbx], 0
	je fsr_replace_loop_exit
	mov r15, rdi
	add r15, rax
	add r15, rbx
	mov r11b, [rdx + rbx]
	mov [r15], r11b
	inc rbx

	jmp fsr_replace_loop
	fsr_replace_loop_exit:

	fsr_inloop_cont:
	mov r15, rdi
	add r15, rax
	add r15, rbx
	cmp [r15], r11b
	jne fsr_inloop_exit ; there's a diff

	inc rbx
	jmp fsr_inloop
	fsr_inloop_exit:

	inc rax
	jmp fsr_loop
	fsr_loop_exit:


retn

ft_strlen:
	xor rax, rax
	loop:
		cmp byte[rdi + rax], 0
		je strlen_exit
		inc rax
		jmp loop
	strlen_exit:
retn

;puts
ft_puts:
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push rax
	push rsi
	push rdx
	push rdi

	call ft_strlen
	mov rdx, rax
	mov rax, 1
	mov rsi, rdi
	mov rdi, 1
	syscall
	pop rdi
	pop rdx
	pop rsi
	pop rax
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rbx
retn