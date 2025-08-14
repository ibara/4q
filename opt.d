/+
 + Copyright (c) 2025 Brian Callahan <bcallah@openbsd.org>
 +
 + Permission to use, copy, modify, and distribute this software for any
 + purpose with or without fee is hereby granted, provided that the above
 + copyright notice and this permission notice appear in all copies.
 +
 + THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 + WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 + MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 + ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 + WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 + ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 + OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 +/

module opt;

class Opt {
    string push_opt_elf = ".text
.section .text..push,\"ax\",@progbits
.globl .push
.push:
	movq .sp(%rip), %rcx
	movq .sz(%rip), %rax
	movq %rcx, %rdx
	shlq $3, %rdx
	cmpq %rdx, %rax
	jz .L1
.L0:
	movq .stack(%rip), %rax
	movq %rdi, (%rax, %rdx, 1)
	incq %rcx
	movq %rcx, .sp(%rip)
	ret
.L1:
	pushq %rbp
	movq %rsp, %rbp
	pushq %rdi
	xchgq %rax, %rdi
	call .resize
	popq %rdi
	leave
	jmp .L0
.type .push, @function
.size .push, .-.push
/* end function .push */
";

    string push_opt_macho = ".text
.globl _.push
_.push:
	movq _.sp(%rip), %rcx
	movq _.sz(%rip), %rax
	movq %rcx, %rdx
	shlq $3, %rdx
	cmpq %rdx, %rax
	jz L1
L0:
	movq _.stack(%rip), %rax
	movq %rdi, (%rax, %rdx, 1)
	incq %rcx
	movq %rcx, _.sp(%rip)
	ret
L1:
	pushq %rbp
	movq %rsp, %rbp
	pushq %rdi
	xchgq %rax, %rdi
	call _.resize
	popq %rdi
	leave
	jmp L0
/* end function .push */
";

    string pop_opt_elf = ".text
.section .text..pop,\"ax\",@progbits
.globl .pop
.pop:
	movq .sp(%rip), %rcx
	cmpq $0, %rcx
	jz .L2
	movq .stack(%rip), %rax
	decq %rcx
	movq %rcx, .sp(%rip)
	shlq $3, %rcx
	movq (%rax, %rcx, 1), %rax
	ret
.L2:
	leaq .str.underflow(%rip), %rdi
	callq .fatal
.type .pop, @function
.size .pop, .-.pop
/* end function .pop */
";

    string pop_opt_macho = ".text
.globl _.pop
_.pop:
	movq _.sp(%rip), %rcx
	cmpq $0, %rcx
	jz L2
	movq _.stack(%rip), %rax
	decq %rcx
	movq %rcx, _.sp(%rip)
	shlq $3, %rcx
	movq (%rax, %rcx, 1), %rax
	ret
L2:
	leaq _.str.underflow(%rip), %rdi
	callq _.fatal
/* end function .pop */
";
}
