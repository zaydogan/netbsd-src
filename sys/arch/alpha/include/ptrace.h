/* $NetBSD: ptrace.h,v 1.9 2017/04/12 18:17:59 kamil Exp $ */

/*
 * Copyright (c) 1994 Christopher G. Demetriou
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Christopher G. Demetriou.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Alpha-dependent ptrace definitions.
 * Note that PT_STEP is _not_ supported.
 */
#define PT_GETREGS      (PT_FIRSTMACH + 0)
#define PT_SETREGS      (PT_FIRSTMACH + 1)
#define PT_GETFPREGS    (PT_FIRSTMACH + 2)
#define PT_SETFPREGS    (PT_FIRSTMACH + 3)

#define PT_MACHDEP_STRINGS \
	"PT_GETREGS", \
	"PT_SETREGS", \
	"PT_GETFPREGS", \
	"PT_SETFPREGS",

#include <machine/reg.h>

#define PTRACE_REG_PC(r)	(r)->r_regs[R_ZERO]
#define PTRACE_REG_SET_PC(r, v)	(r)->r_regs[R_ZERO] = (v)
#define PTRACE_REG_SP(r)	(r)->r_regs[R_SP]
#define PTRACE_REG_INTRV(r)	(r)->r_regs[R_V0]

#define PTRACE_BREAKPOINT	((const uint8_t[]) { 0x80, 0x00, 0x00, 0x00 })
#define PTRACE_BREAKPOINT_ASM	__asm __volatile("bpt" ::: "memory")
#define PTRACE_BREAKPOINT_SIZE	4
