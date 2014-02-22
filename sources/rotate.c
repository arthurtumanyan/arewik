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

bool is_wrotate_time(int router_counter, off_t sz) {
    double mod;

    if (globals.routes[router_counter].rotate_method == BYSIZE) {
        if (sz > 0) {
            off_t size = sz;
            off_t limit = globals.routes[router_counter].rotate_file_limit;
            if (size <= 0 || 0 >= limit) return false;
            mod = (size / limit);
            if (mod > 0 && is_int(mod)) {
                return true;
            }
        }
    }

    return false;
}

bool is_rotate_time(int router_counter, char * filename) {
    double mod;

    if (globals.routes[router_counter].rotate_method == BYSIZE) {
        if (NULL != filename) {
            off_t size = get_file_size(filename);
            off_t limit = globals.routes[router_counter].rotate_file_limit;
            if (size <= 0 || 0 >= limit) return false;
            mod = (size / limit);
            if (mod > 0 && is_int(mod)) {
                return true;
            }
        }
    }

    return false;
}

void scan_for_rotate(int rc, int cc) {

    if (is_rotate_time(rc, files[rc][cc].filename)) {
        do_rotate(rc, cc);
    }
}/* scan for rotate */

/**
 * 
 * If you switch compression on/off or switch from one compression type to another, rotate will not work
 * for current connections. You should reconnect or just restart the program (not reconfigure!)
 * 
 * 
 * @param rc
 * @param cc
 */
void do_rotate(int rc, int cc) {

    if ((globals.routes[rc].rotate == false) || (globals.routes[rc].enabled == false)) {
        return;
    }
    /* check for plain files */
    if (0 == strcmp(globals.routes[rc].router, "plain") && !globals.routes[rc].use_compression) {

        if (NULL != plain_fd[rc][cc]) {
            TRANSFER_ACTIONS[rc][cc] = PAUSE;
            close_plain_file(rc, cc);
            plain_fd[rc][cc] = open_plain_file(globals.routes[rc].to, rc, cc);
            TRANSFER_ACTIONS[rc][cc] = START;
        }
    } else if (0 == strcmp(globals.routes[rc].router, "plain") && (globals.routes[rc].use_compression && globals.routes[rc].compressor == GZIP)) {

        if (Z_NULL != gzip_fd[rc][cc]) {
            TRANSFER_ACTIONS[rc][cc] = PAUSE;
            close_gzip_file(rc, cc);
            gzip_fd[rc][cc] = open_gzip_file(globals.routes[rc].to, rc, cc);
            TRANSFER_ACTIONS[rc][cc] = START;
        }
    } else if (0 == strcmp(globals.routes[rc].router, "plain") && (globals.routes[rc].use_compression && globals.routes[rc].compressor == SNAPPY)) {

        if (NULL != snappy_fd[rc][cc]) {
            TRANSFER_ACTIONS[rc][cc] = PAUSE;
            close_snappy_file(rc, cc);
            snappy_fd[rc][cc] = open_snappy_file(globals.routes[rc].to, rc, cc);
            TRANSFER_ACTIONS[rc][cc] = START;
        }
        /* check for buffer files */
    } else if (globals.routes[rc].is_active && (0 == strcmp(globals.routes[rc].router, "webhdfs"))) {
        if (NULL != webhdfs_fd[rc][cc].fd) {
            TRANSFER_ACTIONS[rc][cc] = PAUSE;
            do_webhdfs_rotate(rc, cc);
            TRANSFER_ACTIONS[rc][cc] = START;
        }
    } else if (!globals.routes[rc].is_active && globals.routes[rc].buffering) {
        if (NULL != buffer_fd[rc][cc]) {
            TRANSFER_ACTIONS[rc][cc] = PAUSE;
            close_buffer(rc, cc);
            buffer_fd[rc][cc] = open_buffer(rc, cc);
            TRANSFER_ACTIONS[rc][cc] = START;
        }
    }
}
