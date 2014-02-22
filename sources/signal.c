/*
Copyright [2013] [Arthur Tumanyan <arthurtumanyan@gmail.com]
Copyright [2013] [Netangels,LLC www.netangels.net]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "arewik.h"
#include "protos.h"

/* Many thanks to R.Stevens */

typedef void Sigfunc(int);

Sigfunc * signal(int signo, Sigfunc *func) {
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (signo == SIGALRM) {

        act.sa_flags |= SA_INTERRUPT; /* SunOS 4.x */

    } else {

        act.sa_flags |= SA_RESTART; /* SVR4, 44BSD */

    }
    if (sigaction(signo, &act, &oact) < 0)
        return (SIG_ERR);
    return (oact.sa_handler);
}

/* end signal */

Sigfunc * Signal(int signo, Sigfunc *func) /* for our signal() function */ {
    Sigfunc *sigfunc;

    if ((sigfunc = signal(signo, func)) == SIG_ERR) {
        // todo
    }
    return (sigfunc);
}

void signal_term(int sig) {
    writeToCustomLog("Caught signal...");
    halt();
}

void set_sig_handler() {

    Signal(SIGINT, SIG_IGN);
    Signal(SIGHUP, SIG_IGN);
    Signal(SIGUSR1, SIG_IGN);
    Signal(SIGUSR2, SIG_IGN);
    Signal(SIGTRAP, SIG_IGN);
    Signal(SIGCHLD, SIG_IGN);
    Signal(SIGTSTP, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);
    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGABRT, SIG_IGN);
    Signal(SIGPIPE, SIG_IGN);
    Signal(SIGALRM, SIG_IGN);
    Signal(SIGSEGV, SIG_IGN);
    Signal(SIGBUS, SIG_IGN);
    Signal(SIGWINCH, SIG_IGN);
    Signal(SIGTERM, signal_term);


}
