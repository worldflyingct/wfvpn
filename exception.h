#ifndef EXCEPTION_H_
#define EXCEPTION_H_

// #define EXCEPTION_DEBUG

// MANPROCSIGnals.
#define MANPROCSIG_HUP  1 // Hangup (POSIX).
#define MANPROCSIG_INT  2 // Interrupt (ANSI).
#define MANPROCSIG_QUIT  3 // Quit (POSIX).
#define MANPROCSIG_ILL  4 // Illegal instruction (ANSI).
#define MANPROCSIG_TRAP  5 // Trace trap (POSIX).
#define MANPROCSIG_ABRT  6 // Abort (ANSI).
#define MANPROCSIG_IOT  6 // IOT trap (4.2 BSD).
#define MANPROCSIG_BUS  7 // BUS error (4.2 BSD).
#define MANPROCSIG_FPE  8 // Floating-point exception (ANSI).
#define MANPROCSIG_KILL  9 // Kill, unblockable (POSIX).
#define MANPROCSIG_USR1  10 // User-defined MANPROCSIG_nal 1 (POSIX).
#define MANPROCSIG_SEGV  11 // Segmentation violation (ANSI).
#define MANPROCSIG_USR2  12 // User-defined MANPROCSIG_nal 2 (POSIX).
#define MANPROCSIG_PIPE  13 // Broken pipe (POSIX).
#define MANPROCSIG_ALRM  14 // Alarm clock (POSIX).
#define MANPROCSIG_TERM  15 // Termination (ANSI).
#define MANPROCSIG_STKFLT 16 // Stack fault.
#define MANPROCSIG_CLD  MANPROCSIG_CHLD // Same as MANPROCSIG_CHLD (System V).
#define MANPROCSIG_CHLD  17 // Child status has changed (POSIX).
#define MANPROCSIG_CONT  18 // Continue (POSIX).
#define MANPROCSIG_STOP  19 // Stop, unblockable (POSIX).
#define MANPROCSIG_TSTP  20 // Keyboard stop (POSIX).
#define MANPROCSIG_TTIN  21 // Background read from tty (POSIX).
#define MANPROCSIG_TTOU  22 // Background write to tty (POSIX).
#define MANPROCSIG_URG  23 // Urgent condition on socket (4.2 BSD).
#define MANPROCSIG_XCPU  24 // CPU limit exceeded (4.2 BSD).
#define MANPROCSIG_XFSZ  25 // File size limit exceeded (4.2 BSD).
#define MANPROCSIG_VTALRM 26 // Virtual alarm clock (4.2 BSD).
#define MANPROCSIG_PROF  27 // Profiling alarm clock (4.2 BSD).
#define MANPROCSIG_WINCH 28 // Window size change (4.3 BSD, Sun).
#define MANPROCSIG_POLL  MANPROCSIG_IO // Pollable event occurred (System V).
#define MANPROCSIG_IO  29 // I/O now possible (4.2 BSD).
#define MANPROCSIG_PWR  30 // Power failure restart (System V).
#define MANPROCSIG_SYS  31 // Bad system call.
#define MANPROCSIG_UNUSED 31

#ifdef EXCEPTION_DEBUG
void addTrace(const char *funcname, int size);
#endif

void ListenSig();

#endif
