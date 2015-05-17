/*
 *  Multi-precision integer library
 *
 *  Copyright (C) 2006-2007  Christophe Devine
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of XySSL nor the names of its contributors may be
 *      used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \file bn_mul.h
 */
/*
 *      Multiply source vector [s] with b, add result
 *       to destination vector [d] and set carry c.
 *
 *      Currently supports:
 *
 *         . IA-32 (386+)         
 *         . AMD64 / EM64T
 *         . IA-32 (SSE2)         
 *         . C, longlong          . C, generic
 */
#ifndef XYSSL_BN_MUL_H
#define XYSSL_BN_MUL_H

//#define HAVE_UNSIGNED_LONG_LONG
//#define BIGNUM_ASM

#ifdef BIGNUM_ASM

#if defined(__i386__)
#define MULADDC_INIT                            \
    asm( "movl   %%ebx, %0      " : "=m" (t));  \
    asm( "movl   %0, %%esi      " :: "m" (s));  \
    asm( "movl   %0, %%edi      " :: "m" (d));  \
    asm( "movl   %0, %%ecx      " :: "m" (c));  \
    asm( "movl   %0, %%ebx      " :: "m" (b));

#define MULADDC_CORE                            \
    asm( "lodsl                 " );            \
    asm( "mull   %ebx           " );            \
    asm( "addl   %ecx,   %eax   " );            \
    asm( "adcl   $0,     %edx   " );            \
    asm( "addl   (%edi), %eax   " );            \
    asm( "adcl   $0,     %edx   " );            \
    asm( "movl   %edx,   %ecx   " );            \
    asm( "stosl                 " );

#define MULADDC_STOP                            \
    asm( "movl   %0, %%ebx      " :: "m" (t));  \
    asm( "movl   %%ecx, %0      " : "=m" (c));  \
    asm( "movl   %%edi, %0      " : "=m" (d));  \
    asm( "movl   %%esi, %0      " : "=m" (s) :: \
    "eax", "ecx", "edx", "esi", "edi" );

#define MULADDC_HUIT                            \
    asm( "movd     %ecx,     %mm1     " );      \
    asm( "movd     %ebx,     %mm0     " );      \
    asm( "movd     (%edi),   %mm3     " );      \
    asm( "paddq    %mm3,     %mm1     " );      \
    asm( "movd     (%esi),   %mm2     " );      \
    asm( "pmuludq  %mm0,     %mm2     " );      \
    asm( "movd     4(%esi),  %mm4     " );      \
    asm( "pmuludq  %mm0,     %mm4     " );      \
    asm( "movd     8(%esi),  %mm6     " );      \
    asm( "pmuludq  %mm0,     %mm6     " );      \
    asm( "movd     12(%esi), %mm7     " );      \
    asm( "pmuludq  %mm0,     %mm7     " );      \
    asm( "paddq    %mm2,     %mm1     " );      \
    asm( "movd     4(%edi),  %mm3     " );      \
    asm( "paddq    %mm4,     %mm3     " );      \
    asm( "movd     8(%edi),  %mm5     " );      \
    asm( "paddq    %mm6,     %mm5     " );      \
    asm( "movd     12(%edi), %mm4     " );      \
    asm( "paddq    %mm4,     %mm7     " );      \
    asm( "movd     %mm1,     (%edi)   " );      \
    asm( "movd     16(%esi), %mm2     " );      \
    asm( "pmuludq  %mm0,     %mm2     " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "movd     20(%esi), %mm4     " );      \
    asm( "pmuludq  %mm0,     %mm4     " );      \
    asm( "paddq    %mm3,     %mm1     " );      \
    asm( "movd     24(%esi), %mm6     " );      \
    asm( "pmuludq  %mm0,     %mm6     " );      \
    asm( "movd     %mm1,     4(%edi)  " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "movd     28(%esi), %mm3     " );      \
    asm( "pmuludq  %mm0,     %mm3     " );      \
    asm( "paddq    %mm5,     %mm1     " );      \
    asm( "movd     16(%edi), %mm5     " );      \
    asm( "paddq    %mm5,     %mm2     " );      \
    asm( "movd     %mm1,     8(%edi)  " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "paddq    %mm7,     %mm1     " );      \
    asm( "movd     20(%edi), %mm5     " );      \
    asm( "paddq    %mm5,     %mm4     " );      \
    asm( "movd     %mm1,     12(%edi) " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "paddq    %mm2,     %mm1     " );      \
    asm( "movd     24(%edi), %mm5     " );      \
    asm( "paddq    %mm5,     %mm6     " );      \
    asm( "movd     %mm1,     16(%edi) " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "paddq    %mm4,     %mm1     " );      \
    asm( "movd     28(%edi), %mm5     " );      \
    asm( "paddq    %mm5,     %mm3     " );      \
    asm( "movd     %mm1,     20(%edi) " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "paddq    %mm6,     %mm1     " );      \
    asm( "movd     %mm1,     24(%edi) " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "paddq    %mm3,     %mm1     " );      \
    asm( "movd     %mm1,     28(%edi) " );      \
    asm( "addl     $32,      %edi     " );      \
    asm( "addl     $32,      %esi     " );      \
    asm( "psrlq    $32,      %mm1     " );      \
    asm( "movd     %mm1,     %ecx     " );

#endif /* i386 */

#if defined(__amd64__) || defined (__x86_64__)

#define MULADDC_INIT                            \
    asm( "movq   %0, %%rsi      " :: "m" (s));  \
    asm( "movq   %0, %%rdi      " :: "m" (d));  \
    asm( "movq   %0, %%rcx      " :: "m" (c));  \
    asm( "movq   %0, %%rbx      " :: "m" (b));  \
    asm( "xorq   %r8, %r8       " );

#define MULADDC_CORE                            \
    asm( "movq  (%rsi),%rax     " );            \
    asm( "mulq   %rbx           " );            \
    asm( "addq   $8,   %rsi     " );            \
    asm( "addq   %rcx, %rax     " );            \
    asm( "movq   %r8,  %rcx     " );            \
    asm( "adcq   $0,   %rdx     " );            \
    asm( "nop                   " );            \
    asm( "addq   %rax, (%rdi)   " );            \
    asm( "adcq   %rdx, %rcx     " );            \
    asm( "addq   $8,   %rdi     " );

#define MULADDC_STOP                            \
    asm( "movq   %%rcx, %0      " : "=m" (c));  \
    asm( "movq   %%rdi, %0      " : "=m" (d));  \
    asm( "movq   %%rsi, %0      " : "=m" (s) :: \
    "rax", "rcx", "rdx", "rbx", "rsi", "rdi", "r8" );

#endif /* AMD64 */


#endif /* GNUC */

#if !defined(MULADDC_CORE)
#ifdef HAVE_UNSIGNED_LONG_LONG
// using 64-bit integer
#define MULADDC_INIT                    \
{                                       \
    t_dbl r;                            \
    t_int r0, r1;

#define MULADDC_CORE                    \
    r   = *(s++) * (t_dbl) b;           \
    r0  = r;                            \
    r1  = r >> biL;                     \
    r0 += c;  r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;

#define MULADDC_STOP                    \
}

#else
#define MULADDC_INIT                    \
{                                       \
    t_int s0, s1, b0, b1;               \
    t_int r0, r1, rx, ry;               \
    b0 = ( b << biH ) >> biH;           \
    b1 = ( b >> biH );

#define MULADDC_CORE                    \
    s0 = ( *s << biH ) >> biH;          \
    s1 = ( *s >> biH ); s++;            \
    rx = s0 * b1; r0 = s0 * b0;         \
    ry = s1 * b0; r1 = s1 * b1;         \
    r1 += ( rx >> biH );                \
    r1 += ( ry >> biH );                \
    rx <<= biH; ry <<= biH;             \
    r0 += rx; r1 += (r0 < rx);          \
    r0 += ry; r1 += (r0 < ry);          \
    r0 +=  c; r1 += (r0 <  c);          \
    r0 += *d; r1 += (r0 < *d);          \
    c = r1; *(d++) = r0;

#define MULADDC_STOP                    \
}

#endif /* C (generic)  */
#endif /* C (longlong) */

#endif /* bn_mul.h */
