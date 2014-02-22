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

void * rotate(void *ptr) {
    int rc, cc;
    sigset_t rotate_sigset;
    int sz = 30;
    char thread_msg[sz];
    //
    set_thread_signalmask(rotate_sigset);
    //
    if (rotate_stop_flag) {
        pthread_mutex_lock(&t_mutex2);
        snprintf(thread_msg, sz, "%s", "Thread was aborted");
        writeToCustomLog(thread_msg);
        pthread_mutex_unlock(&t_mutex2);
        pthread_exit((void *) 0);
    }

    while (!rotate_stop_flag) {

        for (rc = 0; rc < globals.routes_cnt; rc++) {

            if (globals.routes[rc].rotate_method == BYTIME) {
                if (globals.routes[rc].rotate && isTime(globals.routes[rc].rotate_period)) {
                    pthread_mutex_lock(&t_mutex);
                    for (cc = 0; cc < globals.maxcon; cc++) {
                        do_rotate(rc, cc);
                    }
                    pthread_mutex_unlock(&t_mutex);
                }
            }
        }

        //
        sleep(1);
    }
    pthread_mutex_lock(&t_mutex2);
    snprintf(thread_msg, sz, "%s", "Rotator is exiting");
    writeToCustomLog(thread_msg);
    pthread_mutex_unlock(&t_mutex2);
    pthread_exit((void *) 0);
}

/**
 *
 * @param ptr
 * @return
 */
void * watchdog(void *ptr) {

    sigset_t watchdog_sigset;
    int sz = 50, len = 0;
    char thread_msg[sz];
    //
    set_thread_signalmask(watchdog_sigset);
    //
    if (watchdog_stop_flag) {
        pthread_mutex_lock(&t_mutex2);
        snprintf(thread_msg, sz, "%s", "Thread was aborted");
        writeToCustomLog(thread_msg);
        pthread_mutex_unlock(&t_mutex2);
        pthread_exit((void *) 0);
    }

    while (!watchdog_stop_flag) {
        pthread_mutex_lock(&buffer_mutex);
        if (isTime(globals.watchdog_interval)) {
            snprintf(thread_msg, sz, "%s", "Scanning buffer directory");
            writeToDebugLog(thread_msg);
            if (-1 == ftw(arguments.bufferdir, scan_buffer_dir, 20)) {
                snprintf(thread_msg, sz, "Error: %s", strerror(errno));
                writeToDebugLog(thread_msg);
            }
            snprintf(thread_msg, sz, "%s", "Scanning done");
            writeToDebugLog(thread_msg);

        }
        //
        if (isTime(30)) {
            //
            len = strlen(arguments.logdir) + strlen(globals.custom_logfile_name) + 2;
            char custom_logfile[sz];
            snprintf(custom_logfile, sz, "%s/%s", arguments.logdir, globals.custom_logfile_name);
            //
            if (!FileExists(custom_logfile)) {
                closeCustomLog();
                custom_fd = openCustomLog();
            }
            //
            len = strlen(arguments.logdir) + strlen(globals.debug_logfile_name) + 2;
            char debug_logfile[sz];
            snprintf(debug_logfile, sz, "%s/%s", arguments.logdir, globals.debug_logfile_name);
            //
            if (!FileExists(debug_logfile)) {
                closeDebugLog();
                debug_fd = openDebugLog();
            }
            //
            len = strlen(arguments.logdir) + strlen(globals.connections_logfile_name) + 2;
            char con_logfile[sz];
            snprintf(con_logfile, sz, "%s/%s", arguments.logdir, globals.connections_logfile_name);
            //
            if (!FileExists(con_logfile)) {
                closeConLog();
                conlog_fd = openConLog();
            }
            //
            len = strlen(arguments.logdir) + strlen(globals.access_logfile_name) + 2;
            char access_logfile[sz];
            snprintf(access_logfile, sz, "%s/%s", arguments.logdir, globals.access_logfile_name);
            //
            if (!FileExists(access_logfile)) {
                closeAccessLog();
                access_fd = openAccessLog();
            }
        }
        //
        pthread_mutex_unlock(&buffer_mutex);
        //
        sleep(1);
    }
    //
    pthread_mutex_lock(&t_mutex2);
    snprintf(thread_msg, sz, "%s", "Watchdog is exiting");
    writeToCustomLog(thread_msg);
    pthread_mutex_unlock(&t_mutex2);
    pthread_exit((void *) 0);
}

/**
 *
 * @param ptr
 * @return
 */
void * sheduler(void *ptr) {
    sigset_t sheduler_sigset;
    int sz = 30;
    char thread_msg[sz];
    //
    set_thread_signalmask(sheduler_sigset);
    //
    if (sheduler_stop_flag) {
        pthread_mutex_lock(&t_mutex2);
        snprintf(thread_msg, sz, "%s", "Thread was aborted");
        writeToCustomLog(thread_msg);
        pthread_mutex_unlock(&t_mutex2);
        pthread_exit((void *) 0);
    }

    while (!sheduler_stop_flag) {
        pthread_mutex_lock(&t_mutex);
        if (globals.autoreconfigure && isTime(globals.reconfigure_interval)) {
            reconfigure(arguments.configfile);
        }
        if (isTime(globals.ping_interval)) {
            scan_connections();
        }
        pthread_mutex_unlock(&t_mutex);
        //
        sleep(1);
    }
    pthread_mutex_lock(&t_mutex2);
    snprintf(thread_msg, sz, "%s", "Sheduler is exiting");
    writeToCustomLog(thread_msg);
    pthread_mutex_unlock(&t_mutex2);
    pthread_exit((void *) 0);
}

bool isTime(unsigned int __time) {
    if (__time == 0)return false;
    time_t diff_time = difftime(start_time, time(NULL));
    if (((int) diff_time == __time) || (((int) diff_time % __time) == 0 && (int) diff_time != 0)) {
        return true;
    }
    return false;
}

void set_thread_signalmask(sigset_t SignalSet) {

    sigemptyset(&SignalSet);
    sigaddset(&SignalSet, SIGINT);
    sigaddset(&SignalSet, SIGHUP);
    sigaddset(&SignalSet, SIGUSR1);
    sigaddset(&SignalSet, SIGUSR2);
    sigaddset(&SignalSet, SIGTRAP);
    sigaddset(&SignalSet, SIGCHLD);
    sigaddset(&SignalSet, SIGTSTP);
    sigaddset(&SignalSet, SIGTTOU);
    sigaddset(&SignalSet, SIGTTIN);
    sigaddset(&SignalSet, SIGABRT);
    sigaddset(&SignalSet, SIGPIPE);
    sigaddset(&SignalSet, SIGALRM);
    sigaddset(&SignalSet, SIGSEGV);
    sigaddset(&SignalSet, SIGBUS);

    pthread_sigmask(SIG_BLOCK, &SignalSet, NULL);
}
