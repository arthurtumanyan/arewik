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

/***/
ssize_t Readline(int sockd, void *vptr, size_t maxlen) {
    ssize_t n, rc;
    char c, *buffer;

    buffer = vptr;

    for (n = 1; n < maxlen; n++) {

        if ((rc = read(sockd, &c, 1)) == 1) {
            *buffer++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0;
            else
                break;
        } else {
            if (errno == EINTR)
                continue;
            return -1;
        }
    }

    *buffer = 0;
    return n;
}

/*  Write a line to a socket  */

ssize_t Writeline(int sockd, const void *vptr, size_t n) {
    size_t nleft;
    ssize_t nwritten;
    const char *buffer;

    buffer = vptr;
    nleft = n;

    while (nleft > 0) {
        if ((nwritten = write(sockd, buffer, nleft)) <= 0) {
            if (errno == EINTR)
                nwritten = 0;
            else
                return -1;
        }
        nleft -= nwritten;
        buffer += nwritten;
    }

    return n;
}

/**
 *
 * @param rc
 * @param con_counter
 */
void killClient(int rc, int con_counter) {

    int cfd = active_connections[rc][con_counter].connfd;
    if (-1 != cfd) {
        close(cfd);
        deactivate_connection(rc, con_counter);
    } 
}

/**
 *
 * @param hostname
 * @return
 */
char * nslookup(char *hostname) {

    int sz = 128;
    char func_msg[sz];
    static char ipaddr[16];

    if (!globals.use_resolver) {
        return hostname;
    }

    if (isValidIP(hostname)) {
        return hostname;
    }
    struct addrinfo hints, *res;
    struct in_addr addr;
    int err;

    memset(&hints, 0, sizeof (hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    if ((err = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        snprintf(func_msg, sz, "GETADDRINFO error for host: %s: %d %s", hostname, err, strerror(errno));
        pthread_mutex_lock(&t_error);
        writeToCustomLog(func_msg);
        pthread_mutex_unlock(&t_error);
        return NULL;
    }

    addr.s_addr = ((struct sockaddr_in *) (res->ai_addr))->sin_addr.s_addr;
    if (res)freeaddrinfo(res);
    snprintf(ipaddr, sizeof (ipaddr), "%s", inet_ntoa(addr));
    return ipaddr;
}

// Setup nonblocking socket

int setnonblocking(int sockfd) {
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK | O_ASYNC);
    return 0;
}

bool host_is_alive(char *ipaddr, int portno) {
    int sockfd, rc;
    struct sockaddr_in dst;
    int sz = 128;
    char network_msg[sz];
    /* Create a socket point */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        snprintf(network_msg, sz, "%s", "host_is_alive(): can't create socket");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(network_msg);
        pthread_mutex_unlock(&t_error);
        return false;
    }

    bzero(&dst, sizeof (dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(ipaddr);
    dst.sin_port = htons(portno);

    /* Now connect to the server */
    if ((rc = connect(sockfd, (struct sockaddr*) &dst, sizeof (dst))) < 0) {
        return false;
    }
    close(sockfd);
    return true;
}

void scan_connections() {
    int sz = 128;
    char network_msg[sz];
    int i, j;

    for (i = 0; i < globals.routes_cnt; i++) {

        /* skip checking if route is disabled */
        if (!globals.routes[i].enabled)continue;


        /* RIAK backend's health checking */
        /* skip checking if module is disabled */
        if (0 == strcmp(globals.routes[i].router, "riak")) {
            if (!ensure_module_is_enabled("riak")) {
                continue;
            }

            RIAK_TO R_TO = parseRIAKTo(globals.routes[i].to);

            if (ping_riak(R_TO.ip, R_TO.port, R_TO.proto)) {
                globals.routes[i].is_active = true;
                snprintf(network_msg, sz, "%s  [router id: %d]", "RIAK server is alive", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg);
                pthread_mutex_unlock(&t_error);
            } else {
                globals.routes[i].is_active = false;
                snprintf(network_msg, sz, "%s  [router id: %d]", "RIAK server is dead", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg);
                pthread_mutex_unlock(&t_error);
                if (globals.routes[i].buffering) {
                    snprintf(network_msg, sz, "%s  [router id: %d]", "Data will be stored into the buffer while RIAK server is dead", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                } else {
                    snprintf(network_msg, sz, "%s  [router id: %d]", "Data will be dropped while RIAK server is dead (is buffering disabled ?)", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                }
            }
            /* end of RIAK backend's health checking*/
            /* ElasicSearch backend's health checking */
        } else if (0 == strcmp(globals.routes[i].router, "esearch")) {
            /* skip checking if module is disabled */
            if (!ensure_module_is_enabled("esearch")) {
                continue;
            }

            ESEARCH_TO ES_TO = parseESEARCHTo(globals.routes[i].to);

            if (ping_esearch(ES_TO.dst_ip, ES_TO.dst_port)) {
                globals.routes[i].is_active = true;
                snprintf(network_msg, sz, "%s  [router id: %d]", "ESEARCH server is alive", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg); // remove
                pthread_mutex_unlock(&t_error);
            } else {
                globals.routes[i].is_active = false;
                snprintf(network_msg, sz, "%s  [router id: %d]", "ESEARCH server is dead", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg);
                pthread_mutex_unlock(&t_error);
                if (globals.routes[i].buffering) {
                    snprintf(network_msg, sz, "%s  [router id: %d]", "Data will be stored into the buffer while ESEARCH server is dead", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                } else {
                    snprintf(network_msg, sz, "%s  [router id: %d]", "Data will be dropped while ESEARCH server is dead (is buffering disabled ?)", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                }
            }
            /* end of ElasicSearch backend's health checking */
            /* checking WebHdfs backend's health */
        } else if (0 == strcmp(globals.routes[i].router, "webhdfs")) {
            if (!ensure_module_is_enabled("webhdfs")) {
                continue;
            }

            bzero(globals.active_namenode, NAME_MAX);
            snprintf(globals.active_namenode, NAME_MAX, "%s", get_active_namenode(i));

            if (0 == strncmp(globals.active_namenode, "(null)", 6)) {
                globals.routes[i].is_active = false;

                snprintf(network_msg, sz, "%s  [router id: %d]", "WEBHDFS server is dead", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg);
                pthread_mutex_unlock(&t_error);
                if (globals.routes[i].buffering) {
                    snprintf(network_msg, sz, "%s [router id: %d]", "Data will be stored into the buffer while WEBHDFS server is dead", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                } else {
                    snprintf(network_msg, sz, "%s  [router id: %d]", "Data will be dropped while WEBHDFS server is dead (is buffering disabled ?)", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToDebugLog(network_msg);
                    pthread_mutex_unlock(&t_error);
                }
            } else {
                globals.routes[i].is_active = true;
                snprintf(network_msg, sz, "%s  [router id: %d]", "WEBHDFS server is alive", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToDebugLog(network_msg);
                pthread_mutex_unlock(&t_error);
            }
            /* end of WebHdfs backend's health checking */
        } else if (0 == strcmp(globals.routes[i].router, "plain")) {
            globals.routes[i].is_active = true;
        }

        /* kill stalled clients */
        if (!globals.routes[i].is_active && !globals.routes[i].buffering) {
            for (j = 0; j < globals.maxcon; j++) {
                if (active_connections[i][j

                        ].connfd != -1) {
                    killClient(i, j);
                }
            }
        }
    }
}

/**
 *
 * @param ip
 * @return
 */

int findConnectionIdByIp(char *ipaddr) {
    int i, cno;
    cno = find_proper_router_counter(ipaddr);
    for (i = 0; i < globals.maxcon; i++) {
        if (0 == strcmp(active_connections[cno][i].ip, ipaddr)) {
            return active_connections[cno][i].conno;
            break;
        }
    }
    return -1;
}

void init_active_c_table() {
    int i, j;

    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            bzero(active_connections[i][j].ip, 16);
            active_connections[i][j].port = -1;
            active_connections[i][j].connfd = -1;
            active_connections[i][j].conno = -1;
        }
    }
}

void save_active_connection(char *ipaddr, int portno, int cfd, int i) {

    int sz = 128;
    char network_msg[sz];
    int rc = find_proper_router_counter(ipaddr);
    snprintf(network_msg, sz, "Saving connection state for [%d][%d]", rc, i);
    pthread_mutex_lock(&t_error);
    writeToCustomLog(network_msg);
    pthread_mutex_unlock(&t_error);

    strcpy(active_connections[rc][i].ip, ipaddr);
    active_connections[rc][i].connfd = cfd;
    active_connections[rc][i].port = portno;
    active_connections[rc][i].conno = i;
}

void deactivate_connection(int rc, int i) {

    int sz = 128;
    char network_msg[sz];

    snprintf(network_msg, sz, "Deactivating connection state for [%d][%d]", rc, i);
    pthread_mutex_lock(&t_error);
    writeToCustomLog(network_msg);
    pthread_mutex_unlock(&t_error);

    bzero(active_connections[rc][i].ip, 16);
    active_connections[rc][i].connfd = -1;
    active_connections[rc][i].port = -1;
    active_connections[rc][i].conno = -1;

}

bool contain_active_connections(int rc) {
    int i;
    char *ipaddr;
    ipaddr = get_router_from(rc);
    for (i = 0; i < globals.maxcon; i++) {
        if (0 == strcmp(active_connections[rc][i].ip, ipaddr)) {
            if (active_connections[rc][i].connfd != -1) {
                return true;
            }
        }
    }
    return false;
}
