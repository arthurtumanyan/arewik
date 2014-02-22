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

#ifndef NETWORK_H
#define	NETWORK_H

#define EPOLL_RUN_TIMEOUT -1
#define DEF_CON_COUNTER 0

#ifdef	__cplusplus
extern "C" {
#endif

    int listenfd;
    int s;

    int efd;
    int connfd;
    int init_descr = 0;

    struct epoll_event event;
    struct epoll_event *events;

    struct sockaddr in_addr;
    socklen_t in_len;
    socklen_t clilen;
    struct sockaddr_in cliaddr;
    struct sockaddr_in servaddr;
    char ip[NI_MAXHOST], tmp_ip[NI_MAXHOST], port[NI_MAXSERV];
    int yes = 1;
    char inbuff[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER][MAXLINE];
    //

#ifdef	__cplusplus
}
#endif

#endif	/* NETWORK_H */
