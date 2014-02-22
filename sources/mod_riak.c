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
#include "mod_riak.h"

static size_t parse_ping_result(void *buffer, size_t size, size_t nmemb, r_ping_res *st);

_riak_fd init_riak_module(int counter, int con_counter) {
    int sz = 256;
    char riak_msg[PATH_MAX];

    snprintf(riak_msg, sz, "Riak bucket's key auto generation is %s", (globals.routes[counter].auto_key) ? "enabled" : "disabled");
    pthread_mutex_lock(&t_error);
    writeToDebugLog(riak_msg);
    pthread_mutex_unlock(&t_error);

    riak_fd[counter][con_counter].cp = curl_easy_init();
    if (NULL == riak_fd[counter][con_counter].cp) {
        snprintf(riak_msg, sz, "%s", "Could not initialize curl handle for RIAK");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(riak_msg);
        pthread_mutex_unlock(&t_error);
        return riak_fd[counter][con_counter];
    }

    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_USERAGENT, globals.identline);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_FORBID_REUSE, 0);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_FRESH_CONNECT, 0);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_NOSIGNAL, true);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_WRITEDATA, fopen("/dev/null", "w"));
#if LIBCURL_VERSION_MINOR >= 25
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_TCP_KEEPALIVE, true);
#endif
    curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_VERBOSE, false);

    TRANSFER_ACTIONS[counter][con_counter] = START;

    return riak_fd[counter][con_counter];

}

int process_riak(char * data, char *to, int counter, int con_counter) {
    int sz = 256;
    char riak_msg[sz];
    long http_code = 0;
    struct curl_slist *riak_headers = NULL;
    riak_headers = curl_slist_append(riak_headers, "Content-Type: text/plain");
    CURLcode curl_res;
    RIAK_TO _MY_TO;
    _MY_TO = parseRIAKTo(to);
    //
    if (NULL == to) {
        return 0;
    }
    //
    if (0 == strcmp(_MY_TO.ip, "")) {
        snprintf(riak_msg, sz, "%s", "Invalid or empty destination address for RIAK");
        pthread_mutex_lock(&t_error);
        writeToDebugLog(riak_msg);
        pthread_mutex_unlock(&t_error);
        return 0;
    }
    if (globals.routes[counter].auto_key) {
        snprintf(riak_fd[counter][con_counter].url, PATH_MAX, "%s://%s:%d/buckets/%s/keys/", _MY_TO.proto, _MY_TO.ip, _MY_TO.port, parsePathPrefix(_MY_TO.bucket, counter, con_counter));
    } else {
        snprintf(riak_fd[counter][con_counter].url, PATH_MAX, "%s://%s:%d/buckets/%s/keys/%s?returnbody=true", _MY_TO.proto, _MY_TO.ip, _MY_TO.port, parsePathPrefix(_MY_TO.bucket, counter, con_counter), parsePathPrefix(_MY_TO.key, counter, con_counter));
    }
    /* ------------------------------------------------------------------------ */
    trim(data);

    if (NULL != riak_fd[counter][con_counter].cp) {
        curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_URL, riak_fd[counter][con_counter].url);
        curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) - 1);
        curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_HTTPHEADER, riak_headers);
        if (!globals.routes[counter].auto_key) {
            curl_easy_setopt(riak_fd[counter][con_counter].cp, CURLOPT_CUSTOMREQUEST, "PUT");
        }
        curl_res = curl_easy_perform(riak_fd[counter][con_counter].cp);

        curl_easy_getinfo(riak_fd[counter][con_counter].cp, CURLINFO_RESPONSE_CODE, &http_code);
        // Check for errors
        if (curl_res != CURLE_OK || http_code >= 400) {
            snprintf(riak_msg, sz, "Failed to open '%s' on remote server for appending - %s [HTTP code: %ld]", riak_fd[counter][con_counter].url, curl_easy_strerror(curl_res), http_code);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(riak_msg);
            pthread_mutex_unlock(&t_error);
        } else if (http_code != 200 && http_code != 201) {
            snprintf(riak_msg, sz, "Something goes wrong on %s. %s [HTTP code: %ld]", riak_fd[counter][con_counter].url, curl_easy_strerror(curl_res), http_code);
            pthread_mutex_lock(&t_error);
            writeToDebugLog(riak_msg);
            pthread_mutex_unlock(&t_error);
        }

    }
    if (riak_headers != NULL) {
        curl_slist_free_all(riak_headers);
        riak_headers = NULL;
    }
    return (http_code == 200 || http_code == 201);
}

RIAK_TO parseRIAKTo(char *to) {

    static RIAK_TO rto;
    char dst[CFG_PARAM_LEN];
    char *tmp;
    char *proto;
    char *ip, *tmp_ip;
    char *port;

    snprintf(dst, CFG_PARAM_LEN, "%s", to);
    bzero(rto.ip, 16);
    bzero(rto.bucket, 64);
    bzero(rto.key, 64);
    bzero(rto.proto, 5);
    rto.port = 0;

    int rc = get_routerc_by_dst(to);

    if (NULL == dst)return rto;
    if (NULL != strstr(dst, "http://") || NULL != strstr(dst, "https://")) {
        proto = strtok(dst, ":");
        tmp = strtok(NULL, ":");
    } else {
        proto = "http";
        tmp = strtok(dst, ":");
    }
    tmp_ip = strip_chars(tmp, "/");
    ip = nslookup(tmp_ip);

    if (NULL == ip) {
        return rto;
    }

    port = strtok(NULL, ":");
    if (!isValidPort(port)) {
        rto.port = 0;
    } else {
        rto.port = atoi(port);
    }


    snprintf(rto.proto, 6, "%s", proto);
    snprintf(rto.ip, 16, "%s", ip);
    snprintf(rto.bucket, 64, "%s", globals.routes[rc].bucket);
    snprintf(rto.key, 64, "%s", globals.routes[rc].key);

    FREE(tmp_ip);
    return rto;
}

bool ping_riak(char *ip, int port, char *proto) {

    CURL *hnd;


    if (ip && port && proto) {
        int sz = strlen(ip) + strlen(proto) + 16;
        char ping_url[sz];
        bzero(ping_url, sz);

        if (NULL != (hnd = curl_easy_init())) {
            snprintf(ping_url, sz, "%s://%s:%d/ping", proto, ip, port);

            r_ping_res st;

            curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 0L);
            curl_easy_setopt(hnd, CURLOPT_FRESH_CONNECT, 0L);
            curl_easy_setopt(hnd, CURLOPT_NOSIGNAL, 1L);
#if LIBCURL_VERSION_MINOR >= 25
            curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
#endif
            curl_easy_setopt(hnd, CURLOPT_VERBOSE, 0L);
            curl_easy_setopt(hnd, CURLOPT_URL, ping_url);
            curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, parse_ping_result);
            curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &st);
            curl_easy_perform(hnd);

            if (st.isOK) {
                return true;
            } else return false;
        }
    }
    return false;
}

static size_t parse_ping_result(void *buffer, size_t size, size_t nmemb, r_ping_res *st) {

    if (0 == strcasecmp((char *) buffer, "OK")) {
        st->isOK = true;
    } else {
        st->isOK = false;
    }
    return size * nmemb;
}

void close_riak(int rc, int con_counter) {

    if (riak_fd[rc][con_counter].cp) {
        curl_easy_cleanup(riak_fd[rc][con_counter].cp);
        riak_fd[rc][con_counter].cp = NULL;
        char * riak_msg = "RIAK handle cleaned";
        pthread_mutex_lock(&t_error);
        writeToDebugLog(riak_msg);
        pthread_mutex_unlock(&t_error);
    }
}

void close_riak_handles() {
    int i, j;
    for (i = 0; i < globals.routes_cnt; i++) {
        for (j = 0; j < globals.maxcon; j++)
            if (handles[i][j].nosql_type == RIAK) {
                close_riak(i, j);
            }
    }
}
