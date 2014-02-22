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

FILE * openCustomLog() {
    if (0 == strcasecmp(globals.custom_logfile_name, "")) {
        return NULL;
    }
    int sz = strlen(arguments.logdir) + strlen(globals.custom_logfile_name) + 2;
    char custom_logfile[sz];
    snprintf(custom_logfile, sz, "%s/%s", arguments.logdir, globals.custom_logfile_name);
    //
    if (NULL == (custom_fd = fopen(custom_logfile, "a+"))) {
        printf("Cannot create log file '%s' - %s\n", custom_logfile, strerror(errno));
        exit(EXIT_FAILURE);
    }
    setRightOwner(custom_logfile);
    return access_fd;
}

void closeCustomLog() {
    if (0 != strcasecmp(globals.custom_logfile_name, "")) {
        if (NULL != custom_fd) {
            fclose(custom_fd);
            custom_fd = NULL;
        }
    }
}

void writeToCustomLog(char *log_string) {
    ticks = time(NULL);
    char d_time[25];
    snprintf(d_time, 25, "%.24s", ctime(&ticks));

    if (globals.use_syslog == true) {
        write_syslog(log_string);
        return;
    }

    if (NULL != custom_fd) {
        fprintf(custom_fd, "[%s][pid %d] %s\n", d_time, getpid(), log_string);
        fflush(custom_fd);
    }
    VERBOSE(log_string);
}

/*
 
 */
void write_syslog(char *msg) {
    openlog(globals.identline, LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s", msg);
    closelog();
}

/**
 *
 * @param text
 */
void VERBOSE(char *text) {
    if (arguments.verbosity > 0) {
        fprintf(stdout, "%s\n", text);
        fflush(stdout);
    }
}

/*
 
 */
FILE * openDebugLog() {
    if (0 == strcasecmp(globals.debug_logfile_name, "")) {
        return NULL;
    }
    int sz = strlen(arguments.logdir) + strlen(globals.debug_logfile_name) + 2;
    char debug_logfile[sz];
    snprintf(debug_logfile, sz, "%s/%s", arguments.logdir, globals.debug_logfile_name);
    //
    if (NULL == (debug_fd = fopen(debug_logfile, "a+"))) {
        printf("Cannot create log file '%s' - %s\n", debug_logfile, strerror(errno));
        exit(EXIT_FAILURE);
    }
    setRightOwner(debug_logfile);
    return debug_fd;
}

void closeDebugLog() {
    if (0 != strcasecmp(globals.debug_logfile_name, "")) {
        if (NULL != debug_fd) {
            fclose(debug_fd);
            debug_fd = NULL;
        }
    }
}

void writeToDebugLog(char *log_string) {
    if (arguments.debuginfo == 0) {
        return;
    }
    ticks = time(NULL);
    char d_time[25];
    snprintf(d_time, 25, "%.24s", ctime(&ticks));
    if (NULL != debug_fd) {
        fprintf(debug_fd, "[%s][pid %d] %s\n", d_time, getpid(), log_string);
        fflush(debug_fd);
    }
}

/*
 
 */
FILE * openConLog() {
    if (0 == strcasecmp(globals.connections_logfile_name, "")) {
        return NULL;
    }
    int sz = strlen(arguments.logdir) + strlen(globals.connections_logfile_name) + 2;
    char con_logfile[sz];
    snprintf(con_logfile, sz, "%s/%s", arguments.logdir, globals.connections_logfile_name);
    //
    if (NULL == (conlog_fd = fopen(con_logfile, "a+"))) {
        printf("Cannot create log file '%s' - %s\n", con_logfile, strerror(errno));
        exit(EXIT_FAILURE);
    }
    setRightOwner(con_logfile);
    return conlog_fd;
}

void closeConLog() {
    if (0 != strcasecmp(globals.connections_logfile_name, "")) {
        if (NULL != conlog_fd) {
            fclose(conlog_fd);
            conlog_fd = NULL;
        }
    }
}

void writeToConLog(char *log_string) {
    ticks = time(NULL);
    char d_time[25];
    snprintf(d_time, 25, "%.24s", ctime(&ticks));
    if (NULL != conlog_fd) {
        fprintf(conlog_fd, "[%s][pid %d] %s\n", d_time, getpid(), log_string);
        fflush(conlog_fd);
    }
}

/*
 
 */
FILE * openAccessLog() {
    if (0 == strcasecmp(globals.access_logfile_name, "")) {
        return NULL;
    }
    int sz = strlen(arguments.logdir) + strlen(globals.access_logfile_name) + 2;
    char access_logfile[sz];
    snprintf(access_logfile, sz, "%s/%s", arguments.logdir, globals.access_logfile_name);
    //
    if (NULL == (access_fd = fopen(access_logfile, "a+"))) {
        printf("Cannot create log file '%s' - %s\n", access_logfile, strerror(errno));
        exit(EXIT_FAILURE);
    }
    setRightOwner(access_logfile);
    return access_fd;

}

void writeToAccessLog(char *ip, char *identline, char *authuser, char *request, char *response, long bytes, char *backend) {
    char fmt[64], tstr[64];
    struct timeval tv;
    struct tm *tm;

    gettimeofday(&tv, NULL);
    if ((tm = localtime(&tv.tv_sec)) != NULL) {
        strftime(fmt, sizeof fmt, "%d/%b/%Y %T %z", tm);
        snprintf(tstr, sizeof tstr, fmt, tv.tv_usec);
    }
    if (NULL != access_fd) {
        fprintf(access_fd, "%s %s %s [%s] \"%s\" %s %ld \"-\" \"%s\"\n",

                (ip && (0 != strcasecmp(ip, ""))) ? ip : "-",
                (identline && (0 != strcasecmp(identline, ""))) ? identline : "-",
                (authuser && (0 != strcasecmp(authuser, ""))) ? authuser : "-",
                tstr,
                (request && (0 != strcasecmp(request, ""))) ? request : "-",
                response,
                bytes,
                backend
                );
        fflush(access_fd);
    }
}

void closeAccessLog() {
    if (0 != strcasecmp(globals.access_logfile_name, "")) {
        if (NULL != access_fd) {
            fclose(access_fd);
            access_fd = NULL;
        }
    }
}
