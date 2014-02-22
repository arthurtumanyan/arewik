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
#include "network.h"
#include "protos.h"

/**
 * 
 * @param ip
 * @param port
 * @return 
 */
static int connection_count = 0;
static int workers_cnt = 0;

static int create_and_bind() {

    int sz = 128;
    char network_msg[sz];
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(arguments.listen_host);
    servaddr.sin_port = htons(arguments.listen_port);

    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes)) < 0) {
        snprintf(network_msg, sz, "SETSOCKOPT(): %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        pthread_mutex_unlock(&t_error);
        halt();
    }

    if (0 != bind(listenfd, (struct sockaddr *) &servaddr, sizeof (servaddr))) {
        snprintf(network_msg, sz, "Can not bind on %s: %s", arguments.listen_host, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        pthread_mutex_unlock(&t_error);
        halt();
    }

    return listenfd;
}

void do_listen() {

    int sz = 128;
    int rc = 0;
    char network_msg[sz];

    /* Buffer where events are returned */
    events = calloc(globals.maxcon, sizeof event);

    listenfd = create_and_bind(arguments.listen_host, arguments.listen_port);

    if (0 != setnonblocking(listenfd)) {
        snprintf(network_msg, sz, "Can not make non-blocking socket: - %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        halt();
        pthread_mutex_unlock(&t_error);
    }

    if (-1 == listen(listenfd, globals.maxcon)) {
        snprintf(network_msg, sz, "Can not listen on %s: %s", arguments.listen_host, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        halt();
        pthread_mutex_unlock(&t_error);
    }

    snprintf(network_msg, sz, "Listening on %s:%d", arguments.listen_host, arguments.listen_port);
    pthread_mutex_lock(&t_error);
    writeToCustomLog(network_msg);
    pthread_mutex_unlock(&t_error);

    snprintf(network_msg, sz, "Can serve maximum %d clients", globals.maxcon);
    pthread_mutex_lock(&t_error);
    writeToCustomLog(network_msg);
    pthread_mutex_unlock(&t_error);

    efd = epoll_create(globals.maxcon);
    if (-1 == efd) {
        snprintf(network_msg, sz, "Error with epoll initialization: - %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        halt();
        pthread_mutex_unlock(&t_error);
    }
    //
    event.data.fd = listenfd;
    event.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
    //
    if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event)) {
        snprintf(network_msg, sz, "Error with epoll_ctl: - %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        halt();
        pthread_mutex_unlock(&t_error);
    }
    //
    while (!listen_stop_flag) {
        int n, i;
        n = epoll_wait(efd, events, globals.maxcon, globals.epolltimeout);
        for (i = 0; i < n; i++) {
            if (listenfd == events[i].data.fd) {

                in_len = sizeof in_addr;
                connfd = accept(listenfd, &in_addr, &in_len);
                if (connfd == -1) {
                    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                        /* We have processed all incoming
                           connections. */
                        continue;
                    } else {
                        snprintf(network_msg, sz, "Can not accept: %s", strerror(errno));
                        pthread_mutex_lock(&t_error);
                        writeToCustomLog(network_msg);
                        pthread_mutex_unlock(&t_error);
                        continue;
                    }
                }

                if (connection_count == globals.maxcon) {
                    snprintf(network_msg, sz, "Connections count limit exceeded [%d]", connection_count);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                    close(connfd);
                    continue;
                }
                if (0 == getnameinfo(&in_addr, in_len, ip, sizeof ip, port, sizeof port, NI_NUMERICHOST | NI_NUMERICSERV)) {
                    snprintf(network_msg, sz, "Connection attempt from %s,port %d", ip, atoi(port));
                    pthread_mutex_lock(&t_error);
                    writeToConLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                }
                if (-1 == (rc = has_applicable_route(ip))) {
                    Writeline(connfd, NOT_APPLICABLE_ROUTE, strlen(NOT_APPLICABLE_ROUTE));
                    close(connfd);
                    continue;
                }
                //
                if (0 != setnonblocking(connfd)) {
                    snprintf(network_msg, sz, "Can not make non-blocking socket: - %s", strerror(errno));
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(network_msg);
                    halt();
                    pthread_mutex_unlock(&t_error);
                }

                if (workers_cnt == globals.workers) {
                    snprintf(network_msg, sz, "You are about to reach max-worker[%d] limit. Will drop connection", globals.workers);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                    close(connfd);
                    continue;
                }

                event.data.fd = connfd;
                event.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

                if (0 > epoll_ctl(efd, EPOLL_CTL_ADD, connfd, &event)) {
                    snprintf(network_msg, sz, "Error with epoll_ctl: - %s", strerror(errno));
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                    continue;
                }
                //
                connection_count++;
                snprintf(network_msg, sz, "Connection %d established from %s,port %d", connection_count, ip, atoi(port));
                pthread_mutex_lock(&t_error);
                writeToConLog(network_msg);

                snprintf(network_msg, sz, "Connections count = %d\n", connection_count);
                writeToConLog(network_msg);
                pthread_mutex_unlock(&t_error);
                //
                Writeline(connfd, welcome, strlen(welcome));

                PROC_THREAD_PARAMS param;
                snprintf(param.ip, 16, "%s", ip);
                param.port = atoi(port);
                param.connfd = connfd;
                param.counter = rc;
                param.con_counter = DEF_CON_COUNTER;
                param.epoll = efd;
                param.events = &event;
                if (0 == pthread_create(&p_child, NULL, spawn_child_processor, &param)) {
                    pthread_mutex_lock(&t_error);
                    workers_cnt++;
                    snprintf(network_msg, sz, "Workers count: %d", workers_cnt);
                    writeToCustomLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                } else {
                    snprintf(network_msg, sz, "Cannot create a thread: %s", strerror(errno));
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                }

                //
            } /* if listenfd */
        } /* for */
        usleep(10);
    } /* while */

    FREE(events);
    close(listenfd);
}

void * spawn_child_processor(void * ptr) {

    sigset_t epoll_sigset;
    int sz = 128;
    char network_msg[sz];
    pid_t tid = syscall(__NR_gettid);
    PROC_THREAD_PARAMS params = *((PROC_THREAD_PARAMS*) ptr);
    int fd = params.connfd;
    int rc = params.counter;
    int epollfd = params.epoll;
    int done = 0;
    ssize_t count;
    struct timeval timeout;
    timeout.tv_sec = globals.socktimeout;
    timeout.tv_usec = 0;


    if (rc == ROUTES_MAX_COUNT && fd == MAX_CON_PER_ROUTER) {
        snprintf(network_msg, sz, "Handle [%d][%d] is reserved for internal use", rc, fd);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        pthread_mutex_unlock(&t_error);
        pthread_exit((void *) 0);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof (timeout)) < 0) {
        snprintf(network_msg, sz, "SETSOCKOPT(): %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        pthread_mutex_unlock(&t_error);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof (timeout)) < 0) {
        snprintf(network_msg, sz, "SETSOCKOPT(): %s", strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        pthread_mutex_unlock(&t_error);
    }

    snprintf(network_msg, sz, "Starting thread ID [%d] to process data from router [id: %d]", tid, globals.routes[params.counter].id);
    pthread_mutex_lock(&t_error);
    writeToDebugLog(network_msg);
    pthread_mutex_unlock(&t_error);

    set_thread_signalmask(epoll_sigset);

    if (0 == pthread_detach(pthread_self())) {
        snprintf(network_msg, sz, "Thread ID [%d] detached", tid);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(network_msg);
        pthread_mutex_unlock(&t_error);
    }

    save_active_connection(params.ip, params.port, fd, fd);

    snprintf(network_msg, sz, "Preparing to open data channel");
    pthread_mutex_lock(&t_error);
    writeToDebugLog(network_msg);
    pthread_mutex_unlock(&t_error);
    if (TRANSFER_ACTIONS[rc][fd] == UNINITIALIZED) {
        if (!init_descriptor(rc, fd)) {
            snprintf(network_msg, sz, "Failed to open data channel");
            pthread_mutex_lock(&t_error);
            writeToDebugLog(network_msg);
            pthread_mutex_unlock(&t_error);
            done = 1;
            goto close_conn;
        }
    } else {
        snprintf(network_msg, sz, "Data channel already exists for router [id %d]", globals.routes[params.counter].id);
        pthread_mutex_lock(&t_error);
        writeToDebugLog(network_msg);
        pthread_mutex_unlock(&t_error);
        Writeline(connfd, NOT_APPLICABLE_ROUTE, strlen(NOT_APPLICABLE_ROUTE));
        done = 1;
        goto close_conn;
    }

    while (1) {

        usleep(1);

        bzero(inbuff[rc][fd], sizeof inbuff[rc][fd]);
        if (globals.routes[rc].readline) {
            count = Readline(fd, inbuff[rc][fd], sizeof inbuff[rc][fd]);
        } else {
            count = read(fd, inbuff[rc][fd], sizeof inbuff[rc][fd]);
        }

        if (count == -1) {
            if (errno == ECONNRESET) {
                snprintf(network_msg, sz, "Connection on descriptor %d [from %s,port %d] aborted", fd, params.ip, params.port);
                pthread_mutex_lock(&t_error);
                writeToConLog(network_msg);
                pthread_mutex_unlock(&t_error);
                done = 1;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                snprintf(network_msg, sz, "Connection on descriptor %d [from %s,port %d] has error: %s", fd, params.ip, params.port, strerror(errno));
                pthread_mutex_lock(&t_error);
                writeToConLog(network_msg);
                pthread_mutex_unlock(&t_error);
                done = 1;
            }
            break;
        } else if (count == 0) {
            done = 1;
            break;
        }


        if (inbuff[rc][fd][0] == '\n' || inbuff[rc][fd][0] == '\0' || (inbuff[rc][fd][0] == '\r' && inbuff[rc][fd][1] == '\n'))continue;

        while (TRANSFER_ACTIONS[rc][fd] != START) {
            if (TRANSFER_ACTIONS[rc][fd] != PAUSE) {
                snprintf(network_msg, sz, "Someone from route [id:%d] sent data to uninitialized data channel. Killing that connection to avoid looping", rc);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg);
                pthread_mutex_unlock(&t_error);
                killClient(rc, fd);
                break;
            } else {
                usleep(100);
            }
        }

        int response = call_module(globals.routes[rc].router, globals.routes[rc].to, inbuff[rc][fd], rc, fd);

        if (0 != strcasecmp(globals.access_logfile_name, "")) {
            pthread_mutex_lock(&t_error);
            writeToAccessLog(params.ip, NULL, NULL, "PUT", (response) ? "200" : "500", strlen(inbuff[rc][fd]), globals.routes[rc].router);
            pthread_mutex_unlock(&t_error);
        }
    } /* while */
close_conn:
    if (done) {
        if (0 > epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &event)) {
            snprintf(network_msg, sz, "Error with epoll_ctl: - %s", strerror(errno));
            pthread_mutex_lock(&t_error);
            writeToCustomLog(network_msg);
            pthread_mutex_unlock(&t_error);
        }
        close(fd);
        close_descriptor(rc, fd);

    }

    deactivate_connection(rc, fd);
    connection_count--;
    snprintf(network_msg, sz, "Connections count = %d\n", connection_count);
    pthread_mutex_lock(&t_error);
    writeToConLog(network_msg);
    snprintf(network_msg, sz, "Terminating thread ID [%d]", tid);
    writeToDebugLog(network_msg);
    workers_cnt--;
    snprintf(network_msg, sz, "Workers count: %d", workers_cnt);
    writeToCustomLog(network_msg);
    pthread_mutex_unlock(&t_error);
    pthread_exit((void *) 0);

}
