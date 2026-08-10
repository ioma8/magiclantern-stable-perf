#ifndef _SYS_CDEFS_H
#define _SYS_CDEFS_H

#ifndef __cplusplus
#define __THROW
#define __BEGIN_DECLS
#define __END_DECLS
#else
#define __THROW throw ()
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#endif

#ifndef __GNUC__
#define __attribute__(xyz)
#define __extension__
#endif

#if (__GNUC__ > 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 96))
#define __pure __attribute__ ((__pure__))
#else
#define __pure
#endif

#if (__GNUC__ == 2) && (__GNUC_MINOR__ < 95)
#define __restrict__
#endif

#ifndef __STRICT_ANSI__
#define restrict __restrict__
#if __GNUC__ < 3
#define __builtin_expect(foo,bar) (foo)
#define __expect(foo,bar) (foo)
#define __malloc__
#else
#define __expect(foo,bar) __builtin_expect((long)(foo),bar)
/* a1ex: this gives a ton of warnings; comment it out */
//~ #define __attribute_malloc__ __attribute__((__malloc__))
#endif
#endif

/* idea for these macros taken from Linux kernel */
#define __likely(foo) __expect((foo),1)
#define __unlikely(foo) __expect((foo),0)

#ifndef __attribute_malloc__
#define __attribute_malloc__
#endif

#define __P(x) x

#define __ptr_t void*

#if defined(__STRICT_ANSI__) && __STDC_VERSION__ + 0 < 199900L
#define inline
#endif

#ifndef __i386__
#define __regparm__(x)
#endif

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 2))
#define __attribute_dontuse__ __attribute__((__deprecated__))
#else
#define __attribute_dontuse__
#define __deprecated__
#endif

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 3))
# define __nonnull(params) __attribute__ ((__nonnull__ params))
#else
# define __nonnull(params)
#endif

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 4))
# define __attribute_used __attribute__ ((__used__))
#else
# define __attribute_used
# define __warn_unused_result__
#endif

#if (__GNUC__ >= 4)
#define __needsNULL__(x) __sentinel__(x)
#else
#define __needsNULL__(x)
#define __sentinel__
#endif

#if (__GNUC__ < 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ < 3))
# define __cold__
# define __hot__
#endif

#if (__GNUC__ < 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ < 3))
#define __attribute_alloc__(x)
#define __attribute_alloc2__(x,y)
#else
#define __attribute_alloc__(x) __attribute__((alloc_size(x))
#define __attribute_alloc2__(x,y) __attribute__((alloc_size(x,y))
#endif

#if (__GNUC__ < 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ < 5))
#define __attribute_const__
#else
#define __attribute_const__ __attribute__((const))
#endif

#if (__GNUC__ < 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ < 8))
#define __attribute_formatarg__(x)
#else
#define __attribute_formatarg__(x) __attribute__((format_arg(x)))
#endif

/*
 * Compatibility with newlib's sys/cdefs.h.
 * These headers are first on the include path, so they shadow the toolchain's
 * sys/cdefs.h.  Newlib headers (e.g. setjmp.h) that get included by this code
 * expect the following macros to exist; without them, gcc-arm-none-eabi >= 15
 * fails to parse e.g. `void longjmp (...) __dead2;`.
 * Guarded with #ifndef so a real newlib cdefs.h can still win when included.
 */
#ifndef __dead2
#if (__GNUC__ > 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 5))
#define __dead2 __attribute__((__noreturn__))
#else
#define __dead2
#endif
#endif

#ifndef __returns_twice
#if defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 8)))
#define __returns_twice __attribute__((__returns_twice__))
#else
#define __returns_twice
#endif
#endif

#ifndef __pure2
#define __pure2 __attribute__((__const__))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef __used
#define __used __attribute__((__used__))
#endif

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

#ifndef __weak_symbol
#define __weak_symbol __attribute__((__weak__))
#endif

#ifndef __restrict
#define __restrict
#endif

#ifndef __restrict_arr
#define __restrict_arr
#endif

#ifndef __EXPORT
#define __EXPORT
#endif

#ifndef __IMPORT
#define __IMPORT
#endif

#ifndef __printflike
#define __printflike(fmtarg, firstvararg)
#endif

#ifndef __scanflike
#define __scanflike(fmtarg, firstvararg)
#endif

#endif
