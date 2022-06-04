
global _start

_start:
	mov rax, 0x00000000000a656e
	push rax
	mov rax, 0x656e616966756f53 ; Soufiane
	push rax
	mov rdi, rsp; store base str
	call ft_strlen
	mov r10, rax; store size

	mov rax, 0x0000006066756f53 ; Souf
	push rax
	mov rsi, rsp

	mov rax, 0x0000006068706f53 ; Soph
	push rax
	mov rdx, rsp
	mov rcx, 4
	call ft_str_replace
	add rsp, 16
	
	mov rax, 0x000000000060656e; ne
	push rax
	mov rsi, rsp

	mov rax, 0x0000000000602120; a!
	push rax
	mov rdx, rsp
	mov rcx, 2
	call ft_str_replace
	
	call ft_puts

	add rsp, 16
	
	mov	rax, 0x3c;
	mov rdi, 0
	syscall; exit(0)
retn

;Replaces each occurence of 'to_replace' by 'with' in 'base_str'
;void ft_str_replace(char *base_str, char *to_replace, char *with, size_t size_base, size_t size_sub)
;                          rdi     ,       rsi       ,       rdx ,        r10	   , rcx 
ft_str_replace:	
	xor rax, rax; int i = 0 
	fsr_loop:
	;check if we're at the end
	cmp rax, r10
	je fsr_loop_exit ; we reached end of base

	xor rbx, rbx; int j = 0;
	fsr_inloop: ; let's check if we can find the str to_replace
	mov r11b, [rsi + rbx]
	cmp r11b, 0x60
	jne fsr_inloop_cont
	;if we reach this than it's time to replace
	push rax 
	call ft_rand ; replace only sometimes
	cmp rax, 0
	je fsr_random_exit
	pop rax
	;check delimiter exception (delimiter = 0x60 for now)
	mov r15, rdi
	add r15, rax
	add r15, rbx
	cmp BYTE[r15], 0x60
	je fsr_replace_loop_exit

	xor rbx, rbx
	;replace string
	fsr_replace_loop:
	
	cmp rbx, rcx
	je fsr_replace_loop_exit
	mov r15, rdi
	add r15, rax
	add r15, rbx
	mov r11b, [rdx + rbx]
	mov [r15], r11b
	inc rbx

	jmp fsr_replace_loop
	fsr_random_exit:
	pop rax
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
ft_rand:
	push r11
	push r15
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push rsi
	push rdx
	push rdi

	mov rax, 0x00000000006d6f64
	push rax
	mov rax, 0x6e61722f7665642f ; /dev/random
	push rax
	mov rdi, rsp; char *filename
	call open_file
	mov rdi, rax
	add rsp, 16
	sub rsp, 1
	
	mov rsi, rsp
	mov rdx, 1
	mov rax, 0
	syscall;read

	cmp BYTE[rsp], 127
	jae fr_one
	fr_zero:
	mov rax, 0
	jmp fr_end
	fr_one: 
	mov rax, 1
	fr_end:

	add rsp, 1

	pop rdi
	pop rdx
	pop rsi
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rbx
	pop r15
	pop r11
retn

open_file:
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 2
	syscall
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



pop rax

mov rax, QWORD[rsp]
add rsp, 8
