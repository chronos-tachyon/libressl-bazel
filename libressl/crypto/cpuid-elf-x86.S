.file	"x86cpuid.s"
.text
.globl	OPENSSL_ia32_cpuid
.type	OPENSSL_ia32_cpuid,@function
.align	16
OPENSSL_ia32_cpuid:
.L_OPENSSL_ia32_cpuid_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	xorl	%edx,%edx
	pushfl
	popl	%eax
	movl	%eax,%ecx
	xorl	$2097152,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	xorl	%eax,%ecx
	xorl	%eax,%eax
	btl	$21,%ecx
	jnc	.L000nocpuid
	.byte	0x0f,0xa2
	movl	%eax,%edi
	xorl	%eax,%eax
	cmpl	$1970169159,%ebx
	setne	%al
	movl	%eax,%ebp
	cmpl	$1231384169,%edx
	setne	%al
	orl	%eax,%ebp
	cmpl	$1818588270,%ecx
	setne	%al
	orl	%eax,%ebp
	jz	.L001intel
	cmpl	$1752462657,%ebx
	setne	%al
	movl	%eax,%esi
	cmpl	$1769238117,%edx
	setne	%al
	orl	%eax,%esi
	cmpl	$1145913699,%ecx
	setne	%al
	orl	%eax,%esi
	jnz	.L001intel
	movl	$2147483648,%eax
	.byte	0x0f,0xa2
	cmpl	$2147483649,%eax
	jb	.L001intel
	movl	%eax,%esi
	movl	$2147483649,%eax
	.byte	0x0f,0xa2
	orl	%ecx,%ebp
	andl	$2049,%ebp
	cmpl	$2147483656,%esi
	jb	.L001intel
	movl	$2147483656,%eax
	.byte	0x0f,0xa2
	movzbl	%cl,%esi
	incl	%esi
	movl	$1,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	btl	$28,%edx
	jnc	.L002generic
	shrl	$16,%ebx
	andl	$255,%ebx
	cmpl	%esi,%ebx
	ja	.L002generic
	andl	$4026531839,%edx
	jmp	.L002generic
.L001intel:
	cmpl	$4,%edi
	movl	$-1,%edi
	jb	.L003nocacheinfo
	movl	$4,%eax
	movl	$0,%ecx
	.byte	0x0f,0xa2
	movl	%eax,%edi
	shrl	$14,%edi
	andl	$4095,%edi
.L003nocacheinfo:
	movl	$1,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	andl	$3220176895,%edx
	cmpl	$0,%ebp
	jne	.L004notintel
	orl	$1073741824,%edx
	andb	$15,%ah
	cmpb	$15,%ah
	jne	.L004notintel
	orl	$1048576,%edx
.L004notintel:
	btl	$28,%edx
	jnc	.L002generic
	andl	$4026531839,%edx
	cmpl	$0,%edi
	je	.L002generic
	orl	$268435456,%edx
	shrl	$16,%ebx
	cmpb	$1,%bl
	ja	.L002generic
	andl	$4026531839,%edx
.L002generic:
	andl	$2048,%ebp
	andl	$4294965247,%ecx
	movl	%edx,%esi
	orl	%ecx,%ebp
	btl	$27,%ecx
	jnc	.L005clear_avx
	xorl	%ecx,%ecx
.byte	15,1,208
	andl	$6,%eax
	cmpl	$6,%eax
	je	.L006done
	cmpl	$2,%eax
	je	.L005clear_avx
.L007clear_xmm:
	andl	$4261412861,%ebp
	andl	$4278190079,%esi
.L005clear_avx:
	andl	$4026525695,%ebp
.L006done:
	movl	%esi,%eax
	movl	%ebp,%edx
.L000nocpuid:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.size	OPENSSL_ia32_cpuid,.-.L_OPENSSL_ia32_cpuid_begin
.globl	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,@function
.align	16
OPENSSL_wipe_cpu:
.L_OPENSSL_wipe_cpu_begin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	leal	OPENSSL_ia32cap_P,%ecx
	movl	(%ecx),%ecx
	btl	$1,(%ecx)
	jnc	.L008no_x87
.long	4007259865,4007259865,4007259865,4007259865,2430851995
.L008no_x87:
	leal	4(%esp),%eax
	ret
.size	OPENSSL_wipe_cpu,.-.L_OPENSSL_wipe_cpu_begin
.globl	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,@function
.align	16
OPENSSL_atomic_add:
.L_OPENSSL_atomic_add_begin:
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	pushl	%ebx
	nop
	movl	(%edx),%eax
.L009spin:
	leal	(%eax,%ecx,1),%ebx
	nop
.long	447811568
	jne	.L009spin
	movl	%ebx,%eax
	popl	%ebx
	ret
.size	OPENSSL_atomic_add,.-.L_OPENSSL_atomic_add_begin
.comm	OPENSSL_ia32cap_P,8,4
.section	.init
	call	OPENSSL_cpuid_setup
