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

/**
 */
void dump_routes(int routenum, char *what, bool showall) {
    int i;
    char s[4];
    snprintf(s, 4, "%d", routenum);
    printf("-----------------------------------------------------------------------------\n");
    printf("| %s %s properties\n", (showall) ? "Routes" : "Route No:", (showall) ? "" : s);
    printf("-----------------------------------------------------------------------------\n");
    for (i = 0; i < globals.routes_cnt; i++) {
        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "id"))))
            printf("ID:\t%20d\n", globals.routes[i].id);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "enabled"))))
            printf("Enabled:\t%14s\n", (globals.routes[i].enabled) ? "Yes" : "No");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "use-compression"))))
            printf("Compression:\t%19s\n", (globals.routes[i].use_compression) ? "Enabled" : "Disabled");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "compressor"))))
            printf("Compressor:\t%17s\n", compressors_table[globals.routes[i].compressor]);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "compression-ratio"))))
            printf("Compression ratio:\t%4d\n", globals.routes[i].compression_ratio);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "rotate"))))
            printf("Rotation:\t%19s\n", (globals.routes[i].rotate) ? "Enabled" : "Disabled");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "rotate-method"))))
            printf("Rotation method:\t%10s\n", (globals.routes[i].rotate_method == BYTIME) ? "By time" : "By size");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "rotate-period"))))
            printf("Rotate period:\t%13d seconds\n", globals.routes[i].rotate_period);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "rotate-file-limit"))))
            printf("Rotate file limit:\t%11ld bytes\n", globals.routes[i].rotate_file_limit);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "if-active"))))
            printf("Active:\t%22s\n", (globals.routes[i].is_active) ? "Yes" : "No");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "use-readline"))))
            printf("Using readline:\t%13s\n", (globals.routes[i].readline) ? "Yes" : "No");
        int src;

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "sources")))) {
            printf("Allowed sources:\n");
            for (src = 0; src < SOURCE_IPNETCNT_PER_ROUTE; src++) {
                if (0 == strcasecmp(globals.routes[i].from[src].address, ""))continue;
                printf("\t\t\t%16s %16s %5d\n",
                        globals.routes[i].from[src].address,
                        globals.routes[i].from[src].netmask,
                        globals.routes[i].from[src].lastoctet_range);
            }
            printf("\n");
        }

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "send-data-by-blocks"))))
            printf("Send data method:\t%10s\n", (globals.routes[i].send_data_by_block) ? "By blocks" : "Default");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "send-data-size"))))
            printf("Send data size:\t%19ld bytes\n", globals.routes[i].send_data_size);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "buffering"))))
            printf("Buffering:\t%19s\n", (globals.routes[i].buffering) ? "Enabled" : "Disabled");

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "buffersize"))))
            printf("Buffer size:\t%19d bytes\n", globals.routes[i].buffersize);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "destination"))))
            printf("Destination:\t%24s\n", globals.routes[i].to);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "backend"))))
            printf("Backend:\t%16s\n", globals.routes[i].router);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "dst-path"))))
            printf("Dst. path:\t%20s\n", globals.routes[i].dst_path);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "dst-path-prefix"))))
            printf("Dst. path prefix:\t%19s\n", globals.routes[i].dst_path_prefix);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "dst-auth-user"))))
            printf("Dst. auth user:\t%15s\n", globals.routes[i].dst_auth_user);

        if (showall || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "only"))) || ((routenum == globals.routes[i].id) && (0 == strcasecmp(what, "dst-auth-pwd"))))
            printf("Dst. auth pwd:\t%15s\n", globals.routes[i].dst_auth_pwd);
    }
    printf("-----------------------------------------------------------------------------\n");
}

void dump_active_connections() {
    int i, j;
    printf("\t\tActive connections\n");
    printf("\t\t%s\t%s\t%s\t%s\n", "IP", "PORT", "CONNFD", "CONNO");

    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++) {
            if (0 != strcmp(active_connections[i][j].ip, "")) {
                printf("[%d][%d]:\t%s\t%d\t%d\t%d\n", i, j, active_connections[i][j].ip, active_connections[i][j].port, active_connections[i][j].connfd, active_connections[i][j].conno);
            }
        }
    }
}

void debug_epoll_event(struct epoll_event ev) {
    printf("fd(%d), ev.events:", ev.data.fd);

    if (ev.events & EPOLLIN)
        printf(" EPOLLIN ");
    if (ev.events & EPOLLOUT)
        printf(" EPOLLOUT ");
    if (ev.events & EPOLLET)
        printf(" EPOLLET ");
    if (ev.events & EPOLLPRI)
        printf(" EPOLLPRI ");
    if (ev.events & EPOLLRDNORM)
        printf(" EPOLLRDNORM ");
    if (ev.events & EPOLLRDBAND)
        printf(" EPOLLRDBAND ");
    if (ev.events & EPOLLWRNORM)
        printf(" EPOLLRDNORM ");
    if (ev.events & EPOLLWRBAND)
        printf(" EPOLLWRBAND ");
    if (ev.events & EPOLLMSG)
        printf(" EPOLLMSG ");
    if (ev.events & EPOLLERR)
        printf(" EPOLLERR ");
    if (ev.events & EPOLLHUP)
        printf(" EPOLLHUP ");
    if (ev.events & EPOLLONESHOT)
        printf(" EPOLLONESHOT ");

    printf("\n");

}
