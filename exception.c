#include "exception.h"

#ifdef EXCEPTION_DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include<signal.h>

static int position = 0;
static char funcnametracestr[32][32];

void addTrace (const char *funcname, int size) {
    if (size > 32) {
        size = 32;
    }
    memcpy(funcnametracestr[position], funcname, size);
    funcnametracestr[position][31] = '\0';
    position++;
    if (position == 32) {
        position = 0;
    }
}

void showTrace () {
    int offset = position;
    printf("functionTrace start:\n");
    while (1) {
        offset++;
        if (offset == 32) {
            offset = 0;
        }
        if (offset == position) {
            return;
        }
        printf("%s\n", funcnametracestr[offset]);
    }
    printf("functionTrace finish.\n");
}

void handle_proc_sig(int signo) {
    if( signo == MANPROCSIG_HUP )
        printf(" Hangup (POSIX). \r\n");
    else if( signo == MANPROCSIG_INT )
        printf(" Interrupt (ANSI). \r\n");
    else if( signo == MANPROCSIG_QUIT )
        printf(" Quit (POSIX). \r\n");
    else if( signo == MANPROCSIG_ILL )
        printf(" Illegal instruction (ANSI). \r\n");
    else if( signo == MANPROCSIG_TRAP )
        printf(" Trace trap (POSIX). \r\n");
    else if( signo == MANPROCSIG_ABRT )
        printf(" Abort (ANSI). \r\n");
    else if( signo == MANPROCSIG_IOT )
        printf(" IOT trap (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_BUS )
        printf(" BUS error (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_FPE )
        printf(" Floating-point exception (ANSI). \r\n");
    else if( signo == MANPROCSIG_KILL )
        printf(" Kill, unblockable (POSIX). \r\n");
    else if( signo == MANPROCSIG_USR1 )
        printf(" User-defined signal if( signo == (POSIX). \r\n");
    else if( signo == MANPROCSIG_SEGV )
        printf(" Segmentation violation (ANSI). \r\n");
    else if( signo == MANPROCSIG_USR2 )
        printf(" User-defined signal 2 (POSIX). \r\n");
    else if( signo == MANPROCSIG_PIPE ) {
        printf(" Broken pipe (POSIX). \r\n");
        return;
    } else if( signo == MANPROCSIG_ALRM )
        printf(" Alarm clock (POSIX). \r\n");
    else if( signo == MANPROCSIG_TERM )
        printf(" Termination (ANSI). \r\n");
    else if( signo == MANPROCSIG_STKFLT )
        printf(" Stack fault. \r\n");
    else if( signo == MANPROCSIG_CLD ) {
        printf(" Same as SIGCHLD (System V). \r\n");
		return;
    } else if( signo == MANPROCSIG_CHLD )
        printf(" Child status has changed (POSIX). \r\n");
    else if( signo == MANPROCSIG_CONT )
        printf(" Continue (POSIX). \r\n");
    else if( signo == MANPROCSIG_STOP )
        printf(" Stop, unblockable (POSIX). \r\n");
    else if( signo == MANPROCSIG_TSTP ) {
        printf(" Keyboard stop (POSIX). \r\n");
		return;
	} else if( signo == MANPROCSIG_TTIN )
        printf(" Background read from tty (POSIX). \r\n");
    else if( signo == MANPROCSIG_TTOU )
        printf(" Background write to tty (POSIX). \r\n");
    else if( signo == MANPROCSIG_URG )
        printf(" Urgent condition on socket (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_XCPU )
        printf(" CPU limit exceeded (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_XFSZ )
        printf(" File size limit exceeded (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_VTALRM )
        printf(" Virtual alarm clock (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_PROF )
        printf(" Profiling alarm clock (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_WINCH )
        printf(" Window size change (4.3 BSD, Sun). \r\n");
    else if( signo == MANPROCSIG_POLL )
        printf(" Pollable event occurred (System V). \r\n");
    else if( signo == MANPROCSIG_IO )
        printf(" I/O now possible (4.2 BSD). \r\n");
    else if( signo == MANPROCSIG_PWR )
        printf(" Power failure restart (System V). \r\n");
    else if( signo == MANPROCSIG_SYS)
        printf(" Bad system call. \r\n");
    else if( signo == MANPROCSIG_UNUSED)
        printf(" Unknow erroe. \r\n");
    showTrace();
    exit(0);
}

void ListenSig () {
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(funcnametracestr, 0, sizeof(funcnametracestr));
    for (int i = 1 ; i <= 31 ; i++) {
        signal(i, handle_proc_sig);
    }
}

#else

#include <stdio.h>
#include <signal.h>

void handle_proc_sig(int signo) {
    if( signo == MANPROCSIG_PIPE ) {
        printf(" Broken pipe (POSIX). \r\n");
        return;
    } else if( signo == MANPROCSIG_CLD ) {
        printf(" Same as SIGCHLD (System V). \r\n");
		return;
    } else if( signo == MANPROCSIG_TSTP ) {
        printf(" Keyboard stop (POSIX). \r\n");
		return;
	}
}

void ListenSig () {
    signal(MANPROCSIG_PIPE, handle_proc_sig);
    signal(MANPROCSIG_CLD, handle_proc_sig);
    signal(MANPROCSIG_TSTP, handle_proc_sig);
}

#endif
