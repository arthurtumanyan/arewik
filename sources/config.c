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
#include "network.h"


/**
 *
 * @param cfile
 * @return
 */
bool has_conv_backend(char *cf_item, int rc);

char *modules_cfg_allowed_keys[MODULES_COUNT][22] = {
    /* plain */
    { "id", "enabled", "source-hosts", "backend", "use-readline",
        "destination",
        "dst-path-prefix",
        "dst-path",
        "use-compression",
        "compressor",
        "compression-ratio",
        "buffering",
        "rotate",
        "rotate-method",
        "rotate-period",
        "rotate-file-limit",
        "", "", "", "", "", ""},

    /* riak */
    { "id", "enabled", "source-hosts", "backend", "use-readline",
        "bucket",
        "key",
        "auto-key",
        "buffering",
        "destination", "", "", "", "", "", "", "", "", "", "", "", ""},

    /* esearch */
    { "id", "enabled", "source-hosts", "backend", "use-readline",
        "index-name", "type-name", "destination", "unique-id", "", "", "", "", "", "", "", "", "", "", "", "", ""},

    /* webhdfs */
    { "id", "enabled", "source-hosts", "backend", "use-readline",
        "dst-auth-user",
        "dst-path-prefix",
        "dst-path",
        "data-by-blocks",
        "data-block-size",
        "use-compression",
        "buffersize",
        "compression-ratio",
        "compressor",
        "buffering",
        "rotate",
        "rotate-method",
        "rotate-period",
        "rotate-file-limit",
        "namenode1", "namenode2", ""}

};

GLOBALS * readConfig(char *cfile) {

    int i = 0, hcnt = 0, flimit = 0, period = 0;

    config_t cfg, *cf;
    const config_setting_t *modules = NULL, *routes = NULL, *source_hosts = NULL;
    int count, shosts_count = 0, n, _comp, sz = 255;
    char config_msg[sz];
    char measure;
    const char * shost = NULL;
    char * resolved = NULL;
    char *module_name = xmalloc(16);
    module_name[0] = '\0';
    /** Temporary data **/
    const char * rcompressor[ROUTES_MAX_COUNT];
    const char * rto[ROUTES_MAX_COUNT];
    const char * rrouter[ROUTES_MAX_COUNT];
    const char * rrotate_method[ROUTES_MAX_COUNT];
    const char * rrotate_period[ROUTES_MAX_COUNT];
    const char * rrotate_file_limit[ROUTES_MAX_COUNT];
    const char * rdst_path_prefix[ROUTES_MAX_COUNT];
    const char * rdst_path[ROUTES_MAX_COUNT];
    const char * rdst_auth_user[ROUTES_MAX_COUNT];
    const char * rdst_auth_pwd[ROUTES_MAX_COUNT];
    const char * sdata_size[ROUTES_MAX_COUNT];
    const char * buffersize[ROUTES_MAX_COUNT];
    const char * indexname[ROUTES_MAX_COUNT];
    const char * typename[ROUTES_MAX_COUNT];
    const char * uniqueid[ROUTES_MAX_COUNT];

    const char * bucket[ROUTES_MAX_COUNT];
    const char * key[ROUTES_MAX_COUNT];

    const char * namenode1[ROUTES_MAX_COUNT];
    const char * namenode2[ROUTES_MAX_COUNT];


    const char * pidfile = NULL;
    const char * logdir = NULL;
    const char * storagedir = NULL;
    const char * bufferdir = NULL;
    const char * user = NULL;
    const char * group = NULL;
    const char * wdir = NULL;
    const char * listen_host = NULL;
    const char * customlog = NULL;
    const char * debuglog = NULL;
    const char * conlog = NULL;
    const char * accesslog = NULL;
    const char * rident = NULL;
    //
    ARW_INT maxcon = 0;
    ARW_INT socktimeout = 0;
    ARW_INT epolltimeout = 0;
    ARW_INT watchdog_interval = 0;
    ARW_INT ping_interval = 0;
    ARW_INT workers = 0;
    ARW_INT reconfigure_interval = 0;
    ARW_INT listen_port = 0;
    ARW_INT router_id = 0;
    ARW_INT tcompression_ratio = 0;
    //

    for (; i < ROUTES_MAX_COUNT; i++) {
        rcompressor[i] = NULL;
        rto[i] = NULL;
        rrouter[i] = NULL;
        rrotate_method[i] = NULL;
        rrotate_period[i] = NULL;
        rrotate_file_limit[i] = NULL;
        rdst_path_prefix[i] = NULL;
        rdst_path[i] = NULL;
        rdst_auth_user[i] = NULL;
        rdst_auth_pwd[i] = NULL;
        sdata_size[i] = NULL;
        buffersize[i] = NULL;
        indexname[i] = NULL;
        typename[i] = NULL;
        uniqueid[i] = NULL;
        bucket[i] = NULL;
        key[i] = NULL;
        namenode1[i] = NULL;
        namenode2[i] = NULL;
    }

    i = 0;
    cf = &cfg;
    config_init(cf);

    if (CONFIG_FALSE == config_read_file(cf, cfile)) {
        snprintf(config_msg, sz, "Line %d - %s. Exiting...\n",
                config_error_line(cf),
                config_error_text(cf));
        config_destroy(cf);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
        exit(EXIT_FAILURE);
    } else {
        snprintf(config_msg, sz, "Reading configuration file '%s'", cfile);
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    if (!config_lookup_int(cf, "maxcon", &maxcon)) {
        snprintf(config_msg, sz, "%s", "Using default value of maxcon");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.maxcon = maxcon;
    }

    if (!config_lookup_int(cf, "sock-timeout", &socktimeout)) {
        snprintf(config_msg, sz, "%s", "Using default value of sock-timeout");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.socktimeout = socktimeout;
        if (0 > globals.socktimeout) {
            globals.socktimeout = 5000;
            snprintf(config_msg, sz, "%s", "Wrong value detected! Using default value of sock-timeout");
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
        }
        globals.socktimeout *= 1000;
    }

    if (!config_lookup_int(cf, "epoll-timeout", &epolltimeout)) {
        snprintf(config_msg, sz, "%s", "Using default value of epoll-timeout");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.epolltimeout = epolltimeout;
        if (globals.epolltimeout < -1) {
            globals.epolltimeout = EPOLL_RUN_TIMEOUT;
            snprintf(config_msg, sz, "%s", "Wrong value detected! Using default value of epoll-timeout");
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
        }
        globals.epolltimeout *= 1000;
    }

    if (globals.maxcon > MAX_CON_PER_ROUTER) {
        globals.maxcon = MAX_CON_PER_ROUTER;
    }

    if (!config_lookup_int(cf, "watchdog-interval", &watchdog_interval)) {
        snprintf(config_msg, sz, "%s", "Using default value of watchdog-interval");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.watchdog_interval = watchdog_interval;
    }
    if (!config_lookup_int(cf, "ping-interval", &ping_interval)) {
        snprintf(config_msg, sz, "%s", "Using default value of ping-interval");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.ping_interval = ping_interval;
    }

    if (!config_lookup_int(cf, "max-workers", &workers)) {
        snprintf(config_msg, sz, "%s", "Using default value of max-workers");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.workers = workers;
    }

    if (!config_lookup_bool(cf, "auto-reconfigure", &globals.autoreconfigure)) {
        snprintf(config_msg, sz, "%s", "Using default value of auto-reconfigure");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    if (!config_lookup_bool(cf, "use-resolver", &globals.use_resolver)) {
        snprintf(config_msg, sz, "%s", "Using default value of use-resolver");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    if (!config_lookup_int(cf, "reconfigure-interval", &reconfigure_interval)) {
        snprintf(config_msg, sz, "%s", "Using default value of reconfigure-interval");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.reconfigure_interval = reconfigure_interval;
    }

    rident = xmalloc(sizeof (char) * 64);
    if (!config_lookup_string(cf, "ident", &rident)) {
        snprintf(config_msg, sz, "%s", "Using default value of ident");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        snprintf(globals.identline, 64, "%s", rident);
        globals.identline[strlen(rident)] = '\0';
        rident = NULL;
    }

    bufferdir = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "bufferdir", &bufferdir)) {
        snprintf(config_msg, sz, "%s", "Using default value of bufferdir");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.bufferdir = xrealloc(arguments.bufferdir, (sizeof (char) * strlen(bufferdir) + 1));
        strcpy(arguments.bufferdir, bufferdir);
        arguments.bufferdir[strlen(bufferdir)] = '\0';

        bufferdir = NULL;
    }

    if (!config_lookup_bool(cf, "debuginfo", &arguments.debuginfo)) {
        snprintf(config_msg, sz, "%s", "Using default value of debuginfo");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    if (!config_lookup_bool(cf, "log-to-syslog", &globals.use_syslog)) {
        snprintf(config_msg, sz, "%s", "Using default value of log-to-syslog");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    if (!config_lookup_bool(cf, "foreground", &arguments.foreground)) {
        snprintf(config_msg, sz, "%s", "Using default value of foreground");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    group = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "group", &group)) {
        snprintf(config_msg, sz, "%s", "Using default value of group");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.group = xrealloc(arguments.group, (sizeof (char) * strlen(group) + 1));
        strcpy(arguments.group, group);
        arguments.group[strlen(group)] = '\0';

        group = NULL;
    }

    user = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "user", &user)) {
        snprintf(config_msg, sz, "%s", "Using default value of user");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.user = xrealloc(arguments.user, (sizeof (char) * strlen(user) + 1));
        strcpy(arguments.user, user);
        arguments.user[strlen(user)] = '\0';

        user = NULL;
    }

    listen_host = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "listen", &listen_host)) {
        snprintf(config_msg, sz, "%s", "Using default value of listen");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        char *addr;
        if (NULL != (addr = nslookup((char *) listen_host))) {
            arguments.listen_host = xrealloc(arguments.listen_host, (sizeof (char) * strlen(addr) + 1));
            strcpy(arguments.listen_host, addr);
            arguments.listen_host[strlen(listen_host)] = '\0';
        }

        listen_host = NULL;
    }

    if (!config_lookup_int(cf, "port", &listen_port)) {
        snprintf(config_msg, sz, "%s", "Using default value of port");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.listen_port = listen_port;
    }

    logdir = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "logdir", &logdir)) {
        snprintf(config_msg, sz, "%s", "Using default value of logdir");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.logdir = xrealloc(arguments.logdir, (sizeof (char) * strlen(logdir) + 1));
        strcpy(arguments.logdir, logdir);
        arguments.logdir[strlen(logdir)] = '\0';
        logdir = NULL;
    }

    pidfile = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "pidfile", &pidfile)) {
        snprintf(config_msg, sz, "%s", "Using default value of pidfile");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.pidfile = xrealloc(arguments.pidfile, (sizeof (char) * strlen(pidfile) + 1));
        strcpy(arguments.pidfile, pidfile);
        arguments.pidfile[strlen(pidfile)] = '\0';

        pidfile = NULL;
    }

    storagedir = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "storagedir", &storagedir)) {
        snprintf(config_msg, sz, "%s", "Using default value of storagedir");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.storagedir = xrealloc(arguments.storagedir, (sizeof (char) * strlen(storagedir) + 1));
        strcpy(arguments.storagedir, storagedir);
        arguments.storagedir[strlen(storagedir)] = '\0';

        storagedir = NULL;
    }

    if (!config_lookup_bool(cf, "verbose", &arguments.verbosity)) {
        snprintf(config_msg, sz, "%s", "Using default value of verbose");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    }

    wdir = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "workdir", &wdir)) {
        snprintf(config_msg, sz, "%s", "Using default value of workdir");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        arguments.wdir = xrealloc(arguments.wdir, (sizeof (char) * strlen(wdir) + 1));
        strcpy(arguments.wdir, wdir);
        arguments.wdir[strlen(wdir)] = '\0';

        wdir = NULL;
    }

    customlog = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "custom_log", &customlog)) {
        snprintf(config_msg, sz, "%s", "Using default value of custom_log");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.custom_logfile_name = xrealloc(globals.custom_logfile_name, (sizeof (char) * (strlen(customlog) + 1)));
        strcpy(globals.custom_logfile_name, customlog);
        globals.custom_logfile_name[strlen(customlog)] = '\0';

        customlog = NULL;
    }

    debuglog = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "debug_log", &debuglog)) {
        snprintf(config_msg, sz, "%s", "Using default value of debug_log");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.debug_logfile_name = xrealloc(globals.debug_logfile_name, (sizeof (char) * strlen(debuglog) + 1));
        strcpy(globals.debug_logfile_name, debuglog);
        globals.debug_logfile_name[strlen(debuglog)] = '\0';

        debuglog = NULL;
    }

    conlog = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "connections_log", &conlog)) {
        snprintf(config_msg, sz, "%s", "Using default value of connections_log");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.connections_logfile_name = xrealloc(globals.connections_logfile_name, (sizeof (char) * strlen(conlog) + 1));
        strcpy(globals.connections_logfile_name, conlog);
        globals.connections_logfile_name[strlen(conlog)] = '\0';

        conlog = NULL;
    }

    accesslog = xmalloc(sizeof (char) * CFG_PARAM_LEN);
    if (!config_lookup_string(cf, "access_log", &accesslog)) {
        snprintf(config_msg, sz, "%s", "Using default value of access_log");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
    } else {
        globals.access_logfile_name = xrealloc(globals.access_logfile_name, (sizeof (char) * strlen(accesslog) + 1));
        strcpy(globals.access_logfile_name, accesslog);
        globals.access_logfile_name[strlen(accesslog)] = '\0';

        accesslog = NULL;
    }

    /* looking for modules configuration */
    modules = config_lookup(cf, "modules");
    if (NULL == modules) {
        snprintf(config_msg, sz, "Undefined section '%s'. Exiting.", "modules");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);

        exit(EXIT_FAILURE);
    }
    count = config_setting_length(modules);

    char mods[255];
    bzero(mods, 255);

    for (n = 0; n < count; n++) {
        strcpy(module_name, config_setting_get_string_elem(modules, n));
        module_name[16] = '\0';

        if (module_exists(module_name)) {
            strcat(mods, module_name);
            strcat(mods, " ");
            enableModule(module_name);
        } else {
            snprintf(config_msg, sz, "No such module: '%s'", module_name);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
        }
    }

    if (module_name) {
        FREE(module_name);
        module_name = NULL;
    }

    snprintf(config_msg, sz, "Enabled module%s %s [ %s]", (count == 1) ? "" : "s", (count == 1) ? "is" : "are", mods);
    pthread_mutex_lock(&t_error);
    writeToCustomLog(config_msg);
    pthread_mutex_unlock(&t_error);

    routes = config_lookup(cf, "routes");
    if (NULL == routes) {
        snprintf(config_msg, sz, "Undefined section '%s'. Exiting.", "routes");
        pthread_mutex_lock(&t_error);
        writeToCustomLog(config_msg);
        pthread_mutex_unlock(&t_error);
        exit(EXIT_FAILURE);

    }
    count = config_setting_length(routes);
    if (count > ROUTES_MAX_COUNT)count = ROUTES_MAX_COUNT;
    globals.routes_cnt = count;
    snprintf(config_msg, sz, "Routes count restricted to %d", ROUTES_MAX_COUNT);
    pthread_mutex_lock(&t_error);
    writeToCustomLog(config_msg);
    pthread_mutex_unlock(&t_error);
    //

    //
    for (i = 0; i < count; ++i) {
        config_setting_t *route = config_setting_get_elem(routes, i);

        ////////////////////////////////////////////////////////////////////////////////
        if (!config_setting_lookup_int(route, "id", &router_id)) {
            snprintf(config_msg, sz, "Can not find 'id' for router");
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            globals.routes[i].id = router_id;
        }

        if (!config_setting_lookup_bool(route, "enabled", &globals.routes[i].enabled)) {
            snprintf(config_msg, sz, "Can not find 'enabled' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }
        if (!globals.routes[i].enabled)continue;
        source_hosts = config_setting_get_member(route, "source-hosts");

        if (NULL != source_hosts && CONFIG_TRUE == config_setting_is_array(source_hosts)) {
            shosts_count = config_setting_length(source_hosts);
            for (hcnt = 0; hcnt < shosts_count; hcnt++) {

                shost = config_setting_get_string_elem(source_hosts, hcnt);
                if (0 == strcmp(shost, "")) {
                    shost = "0.0.0.0";
                    snprintf(globals.routes[i].from[hcnt].address, 16, "%s", shost);
                    snprintf(globals.routes[i].from[hcnt].netmask, 16, "%s", "");
                    globals.routes[i].from[hcnt].lastoctet_range = 0;

                } else {
                    if (isSubnet(shost)) {
                        char * tmp;
                        tmp = strdup(shost);
                        char * address = strtok(tmp, "/");
                        char * netmask = strtok(NULL, "/");
                        snprintf(globals.routes[i].from[hcnt].address, 16, "%s", (NULL != (resolved = nslookup((char *) address)) ? resolved : address));
                        snprintf(globals.routes[i].from[hcnt].netmask, 16, "%s", netmask);
                        globals.routes[i].from[hcnt].lastoctet_range = 0;

                    } else if (isIpRange(shost)) {
                        char *tmp;
                        tmp = strdup(shost);
                        char * address = strtok(tmp, "-");
                        char * range = strtok(NULL, "-");
                        snprintf(globals.routes[i].from[hcnt].address, 16, "%s", (NULL != (resolved = nslookup((char *) address)) ? resolved : address));
                        snprintf(globals.routes[i].from[hcnt].netmask, 16, "%s", "");
                        globals.routes[i].from[hcnt].lastoctet_range = atoi(range);

                    } else {
                        /* assuming we have an ordinary hostname now */
                        snprintf(globals.routes[i].from[hcnt].address, 16, "%s", (NULL != (resolved = nslookup((char *) shost)) ? resolved : shost));
                        snprintf(globals.routes[i].from[hcnt].netmask, 16, "%s", "");
                        globals.routes[i].from[hcnt].lastoctet_range = 0;

                    }
                }

            }

        } else {
            snprintf(config_msg, sz, "Undefined subsection '%s' or syntax error . Exiting...", "source_hosts");
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }

        rrouter[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "backend", &rrouter[i])) {
            snprintf(config_msg, sz, "Can not find 'backend' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (0 == strcasecmp(rrouter[i], "")) {
                snprintf(config_msg, sz, "Empty 'backend' for router: id:%d", globals.routes[i].id);
                pthread_mutex_lock(&t_error);
                writeToCustomLog(config_msg);
                pthread_mutex_unlock(&t_error);
                exit(EXIT_FAILURE);
            }
            snprintf(globals.routes[i].router, CFG_PARAM_LEN, "%s", rrouter[i]);
            globals.routes[i].router[strlen(rrouter[i])] = '\0';
            rrouter[i] = NULL;
        }

        if (!config_setting_lookup_bool(route, "use-readline", &globals.routes[i].readline)) {
            snprintf(config_msg, sz, "Can not find 'use-readline' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }
        ////////////////////////////////////////////////////////////////////////////////

        rto[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "destination", &rto[i]) && has_conv_backend("destination", i)) {
            snprintf(config_msg, sz, "Can not find 'destination' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("destination", i)) {
                if (0 == strcasecmp(rto[i], "")) {
                    snprintf(config_msg, sz, "Empty 'destination' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].to, CFG_PARAM_LEN, "%s", rto[i]);
                globals.routes[i].to[strlen(rto[i])] = '\0';
                rto[i] = NULL;
            }
        }

        namenode1[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "namenode1", &namenode1[i]) && has_conv_backend("namenode1", i)) {
            snprintf(config_msg, sz, "Can not find 'namenode1' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("namenode1", i)) {
                if (0 == strcasecmp(namenode1[i], "")) {
                    snprintf(config_msg, sz, "Empty 'namenode1' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].namenode1, NAME_MAX, "%s", namenode1[i]);
                globals.routes[i].namenode1[strlen(namenode1[i])] = '\0';
                namenode1[i] = NULL;
            }
        }

        namenode2[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "namenode2", &namenode2[i]) && has_conv_backend("namenode2", i)) {
            snprintf(config_msg, sz, "Can not find 'namenode2' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("namenode2", i)) {
                if (0 == strcasecmp(namenode2[i], "")) {
                    snprintf(config_msg, sz, "Empty 'namenode2' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].namenode2, NAME_MAX, "%s", namenode2[i]);
                globals.routes[i].namenode2[strlen(namenode2[i])] = '\0';
                namenode2[i] = NULL;
            }
        }

        buffersize[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "buffersize", &buffersize[i]) && has_conv_backend("buffersize", i)) {
            snprintf(config_msg, sz, "Can not find 'buffersize' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("buffersize", i)) {
                if (0 != strcasecmp(buffersize[i], "")) {
                    if (2 == sscanf(buffersize[i], "%d%c", &flimit, &measure)) {
                        if (measure == 'k' || measure == 'K') {
                            globals.routes[i].buffersize = KB * flimit;
                        } else if (measure == 'm' || measure == 'M') {
                            globals.routes[i].buffersize = MB * flimit;
                        } else if (measure == 'g' || measure == 'G') {

                            snprintf(config_msg, sz, "buffersize [%lu] is too big ... Using default size [%ld]. router_id:%d", globals.routes[i].send_data_size, DEFAULT_WEBHDFS_BUFF_SIZE, globals.routes[i].id);
                            pthread_mutex_lock(&t_error);
                            writeToCustomLog(config_msg);
                            pthread_mutex_unlock(&t_error);
                            globals.routes[i].buffersize = DEFAULT_WEBHDFS_BUFF_SIZE;
                        } else if (measure == 't' || measure == 'T') {

                            snprintf(config_msg, sz, "buffersize [%lu] is too big... Using default size [%ld]. router_id:%d", globals.routes[i].send_data_size, DEFAULT_WEBHDFS_BUFF_SIZE, globals.routes[i].id);
                            writeToCustomLog(config_msg);
                            globals.routes[i].buffersize = DEFAULT_WEBHDFS_BUFF_SIZE;
                        }
                    } else {
                        globals.routes[i].buffersize = DEFAULT_WEBHDFS_BUFF_SIZE;
                        snprintf(config_msg, sz, "Using default value of buffersize [%lu] for router: id:%d", globals.routes[i].send_data_size, globals.routes[i].id);
                        pthread_mutex_lock(&t_error);
                        writeToCustomLog(config_msg);
                        pthread_mutex_unlock(&t_error);
                    }
                } else {
                    globals.routes[i].buffersize = DEFAULT_WEBHDFS_BUFF_SIZE;
                    snprintf(config_msg, sz, "Empty 'buffersize' for router id: %d. Using default value of buffersize [%lu]", globals.routes[i].id, globals.routes[i].send_data_size);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                }

                buffersize[i] = NULL;
            }
        }


        sdata_size[i] = xmalloc(sizeof (char) *CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "data-block-size", &sdata_size[i]) && has_conv_backend("data-block-size", i)) {
            snprintf(config_msg, sz, "Can not find 'data-block-size' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("data-block-size", i)) {
                if (0 != strcasecmp(sdata_size[i], "")) {
                    if (2 == sscanf(sdata_size[i], "%d%c", &flimit, &measure)) {
                        if (measure == 'k' || measure == 'K') {
                            globals.routes[i].send_data_size = KB * flimit;
                        } else if (measure == 'm' || measure == 'M') {
                            globals.routes[i].send_data_size = MB * flimit;
                        } else if (measure == 'g' || measure == 'G') {

                            snprintf(config_msg, sz, "data-block-size [%lu] is too big ... Using default size [%ld]. router_id:%d", globals.routes[i].send_data_size, UPLOAD_DATA_BUF_LIMIT, globals.routes[i].id);
                            pthread_mutex_lock(&t_error);
                            writeToCustomLog(config_msg);
                            pthread_mutex_unlock(&t_error);
                            globals.routes[i].send_data_size = UPLOAD_DATA_BUF_LIMIT;
                        } else if (measure == 't' || measure == 'T') {

                            snprintf(config_msg, sz, "data-block-size [%lu] is too big... Using default size [%ld]. router_id:%d", globals.routes[i].send_data_size, UPLOAD_DATA_BUF_LIMIT, globals.routes[i].id);
                            pthread_mutex_lock(&t_error);
                            writeToCustomLog(config_msg);
                            pthread_mutex_unlock(&t_error);
                            globals.routes[i].send_data_size = UPLOAD_DATA_BUF_LIMIT;
                        }
                    } else {
                        globals.routes[i].send_data_size = UPLOAD_DATA_BUF_LIMIT;
                        snprintf(config_msg, sz, "Using default value of data-block-size [%lu] for router: id:%d", globals.routes[i].send_data_size, globals.routes[i].id);
                        pthread_mutex_lock(&t_error);
                        writeToCustomLog(config_msg);
                        pthread_mutex_unlock(&t_error);
                    }
                } else {
                    globals.routes[i].send_data_size = UPLOAD_DATA_BUF_LIMIT;
                    snprintf(config_msg, sz, "Empty 'data-block-size' for router id: %d.Using default value of data-block-size [%lu]", globals.routes[i].id, globals.routes[i].send_data_size);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                }
                if (globals.routes[i].send_data_size > UPLOAD_DATA_BUF_LIMIT) {
                    snprintf(config_msg, sz, "data-block-size [%lu] is too big... Using default size [%ld]. router_id:%d", globals.routes[i].send_data_size, UPLOAD_DATA_BUF_LIMIT, globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    globals.routes[i].send_data_size = UPLOAD_DATA_BUF_LIMIT;
                }

                sdata_size[i] = NULL;
            }
        }



        if (!config_setting_lookup_bool(route, "data-by-blocks", &globals.routes[i].send_data_by_block) && has_conv_backend("data-by-blocks", i)) {
            snprintf(config_msg, sz, "Can not find 'data-by-blocks' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }


        rdst_path_prefix[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "dst-path-prefix", &rdst_path_prefix[i]) && has_conv_backend("dst-path-prefix", i)) {
            snprintf(config_msg, sz, "Can not find 'dst-path-prefix' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("dst-path-prefix", i)) {
                if (0 == strcasecmp(rdst_path_prefix[i], "")) {
                    snprintf(config_msg, sz, "Empty 'dst-path-prefix' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].dst_path_prefix, CFG_PARAM_LEN, "%s", rdst_path_prefix[i]);
                globals.routes[i].dst_path_prefix[strlen(rdst_path_prefix[i])] = '\0';

                rdst_path_prefix[i] = NULL;
            }
        }

        rdst_path[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "dst-path", &rdst_path[i]) && has_conv_backend("dst-path", i)) {
            snprintf(config_msg, sz, "Can not find 'dst-path' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("dst-path", i)) {
                if (0 == strcasecmp(rdst_path[i], "")) {
                    snprintf(config_msg, sz, "Empty 'dst-path-prefix' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].dst_path, CFG_PARAM_LEN, "%s", rdst_path[i]);
                rdst_path[i] = NULL;
            }
        }


        rdst_auth_user[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "dst-auth-user", &rdst_auth_user[i]) && has_conv_backend("dst-auth-user", i)) {
            snprintf(config_msg, sz, "Can not find 'dst-auth-user' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("dst-auth-user", i)) {
                if (0 == strcasecmp(rdst_auth_user[i], "")) {
                    snprintf(config_msg, sz, "Empty 'dst-auth-user' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].dst_auth_user, NAME_MAX, "%s", rdst_auth_user[i]);
                globals.routes[i].dst_auth_user[strlen(rdst_auth_user[i])] = '\0';

                rdst_auth_user[i] = NULL;
            }
        }

        rdst_auth_pwd[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "dst-auth-pwd", &rdst_auth_pwd[i]) && has_conv_backend("dst-auth-pwd", i)) {
            snprintf(config_msg, sz, "Can not find 'dst-auth-pwd' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("dst-auth-pwd", i)) {
                if (0 == strcasecmp(rdst_auth_pwd[i], "")) {
                    snprintf(config_msg, sz, "Empty 'dst-auth-pwd' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].dst_auth_pwd, NAME_MAX, "%s", rdst_auth_pwd[i]);
                globals.routes[i].dst_auth_pwd[strlen(rdst_auth_pwd[i])] = '\0';

                rdst_auth_pwd[i] = NULL;
            }
        }

        indexname[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "index-name", &indexname[i]) && has_conv_backend("index-name", i)) {
            snprintf(config_msg, sz, "Can not find 'index-name' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("index-name", i)) {
                if (0 == strcasecmp(indexname[i], "")) {
                    snprintf(config_msg, sz, "Empty 'index-name' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].index_name, 64, "%s", indexname[i]);
                globals.routes[i].index_name[strlen(indexname[i])] = '\0';

                indexname[i] = NULL;
            }
        }

        uniqueid[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "unique-id", &uniqueid[i]) && has_conv_backend("unique-id", i)) {
            snprintf(config_msg, sz, "Can not find 'unique-id' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("unique-id", i)) {
                if (0 == strcasecmp(uniqueid[i], "")) {
                    snprintf(config_msg, sz, "Empty 'unique-id' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].uniqueid, 64, "%s", uniqueid[i]);
                globals.routes[i].uniqueid[strlen(uniqueid[i])] = '\0';

                uniqueid[i] = NULL;
            }
        }

        typename[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "type-name", &typename[i]) && has_conv_backend("type-name", i)) {
            snprintf(config_msg, sz, "Can not find 'type-name' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("type-name", i)) {
                if (0 == strcasecmp(typename[i], "")) {
                    snprintf(config_msg, sz, "Empty 'type-name' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].type_name, 64, "%s", typename[i]);
                globals.routes[i].type_name[strlen(typename[i])] = '\0';

                typename[i] = NULL;
            }
        }

        bucket[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "bucket", &bucket[i]) && has_conv_backend("bucket", i)) {
            snprintf(config_msg, sz, "Can not find 'bucket' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("bucket", i)) {
                if (0 == strcasecmp(bucket[i], "")) {
                    snprintf(config_msg, sz, "Empty 'bucket' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].bucket, 64, "%s", bucket[i]);
                globals.routes[i].bucket[strlen(bucket[i])] = '\0';

                bucket[i] = NULL;
            }
        }

        key[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "key", &key[i]) && has_conv_backend("key", i)) {
            snprintf(config_msg, sz, "Can not find 'key' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("key", i)) {
                if (0 == strcasecmp(key[i], "")) {
                    snprintf(config_msg, sz, "Empty 'key' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                snprintf(globals.routes[i].key, 64, "%s", key[i]);
                globals.routes[i].key[strlen(key[i])] = '\0';

                key[i] = NULL;
            }
        }


        if (!config_setting_lookup_bool(route, "auto-key", &globals.routes[i].auto_key) && has_conv_backend("auto-key", i)) {
            snprintf(config_msg, sz, "Can not find 'auto-key' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }


        if (!config_setting_lookup_bool(route, "use-compression", &globals.routes[i].use_compression) && has_conv_backend("use-compression", i)) {
            snprintf(config_msg, sz, "Can not find 'use-compression' for router: id:%d", globals.routes[i].id);

            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }

        rcompressor[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "compressor", &rcompressor[i]) && has_conv_backend("compressor", i)) {
            snprintf(config_msg, sz, "Can not find 'compressor' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("compressor", i)) {
                if (0 == strcasecmp(rcompressor[i], "")) {
                    snprintf(config_msg, sz, "Empty 'compressor' for router: id:%d", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    exit(EXIT_FAILURE);
                }
                _comp = get_compressor(rcompressor[i]);
                globals.routes[i].compressor = (-1 == _comp) ? 0 : _comp;
            }
            rcompressor[i] = NULL;
        }

        if (!config_setting_lookup_int(route, "compression-ratio", &tcompression_ratio) && has_conv_backend("compression-ratio", i)) {
            snprintf(config_msg, sz, "Can not find 'compression-ratio' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            globals.routes[i].compression_ratio = tcompression_ratio;
        }

        if (!config_setting_lookup_bool(route, "rotate", &globals.routes[i].rotate) && has_conv_backend("rotate", i)) {
            snprintf(config_msg, sz, "Can not find 'rotate' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }

        rrotate_method[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "rotate-method", &rrotate_method[i]) && has_conv_backend("rotate-method", i)) {
            snprintf(config_msg, sz, "Can not find 'rotate-method' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("rotate-method", i)) {

                if (0 != strcasecmp(rrotate_method[i], "")) {
                    if (0 == strcmp(rrotate_method[i], "by_size")) {
                        globals.routes[i].rotate_method = BYSIZE;
                    } else if (0 == strcmp(rrotate_method[i], "by_time")) {
                        globals.routes[i].rotate_method = BYTIME;
                    } else {
                        globals.routes[i].rotate_method = BYSIZE;
                    }
                } else {
                    globals.routes[i].rotate_method = BYSIZE;
                }
            }

            rrotate_method[i] = NULL;
        }

        rrotate_period[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "rotate-period", &rrotate_period[i]) && has_conv_backend("rotate-period", i)) {
            snprintf(config_msg, sz, "Can not find 'rotate-period' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("rotate-period", i)) {
                if (0 != strcasecmp(rrotate_period[i], "")) {
                    if (2 == sscanf(rrotate_period[i], "%d%c", &period, &measure)) {

                        if (measure == 'm' || measure == 'M') {
                            globals.routes[i].rotate_period = (period * 60);
                        } else if (measure == 'h' || measure == 'H') {
                            globals.routes[i].rotate_period = (period * 3600);
                        }

                    } else {
                        globals.routes[i].rotate_period = 3600;
                        snprintf(config_msg, sz, "Using default value of rotate-period [%d] for router: id:%d", globals.routes[i].rotate_period, globals.routes[i].id);
                        pthread_mutex_lock(&t_error);
                        writeToCustomLog(config_msg);
                        pthread_mutex_unlock(&t_error);
                    }
                } else {
                    globals.routes[i].rotate_period = 3600;
                    snprintf(config_msg, sz, "Using default value of rotate-period [%d] for router: id:%d", globals.routes[i].rotate_period, globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                }
            }

            rrotate_period[i] = NULL;
        }

        rrotate_file_limit[i] = xmalloc(sizeof (char) * CFG_PARAM_LEN);
        if (!config_setting_lookup_string(route, "rotate-file-limit", &rrotate_file_limit[i]) && has_conv_backend("rotate-file-limit", i)) {
            snprintf(config_msg, sz, "Can not find 'rotate-file-limit' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        } else {
            if (has_conv_backend("rotate-file-limit", i)) {
                if (0 != strcasecmp(rrotate_file_limit[i], "")) {
                    if (2 == sscanf(rrotate_file_limit[i], "%d%c", &flimit, &measure)) {
                        if (measure == 'k' || measure == 'K') {
                            globals.routes[i].rotate_file_limit = KB * flimit;
                        } else if (measure == 'm' || measure == 'M') {
                            globals.routes[i].rotate_file_limit = MB * flimit;
                        } else if (measure == 'g' || measure == 'G') {
                            globals.routes[i].rotate_file_limit = GB * flimit;
                        } else if (measure == 't' || measure == 'T') {
                            globals.routes[i].rotate_file_limit = TB * flimit;
                        }
                    } else {
                        globals.routes[i].rotate_file_limit = GB;
                        snprintf(config_msg, sz, "Using default value of rotate-file-limit [%lu] for router: id:%d", globals.routes[i].rotate_file_limit, globals.routes[i].id);
                        pthread_mutex_lock(&t_error);
                        writeToCustomLog(config_msg);
                        pthread_mutex_unlock(&t_error);
                    }
                } else {
                    globals.routes[i].rotate_file_limit = GB;
                    snprintf(config_msg, sz, "Using default value of rotate-file-limit [%lu] for router: id:%d", globals.routes[i].rotate_file_limit, globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                }
            }

            rrotate_file_limit[i] = NULL;
        }


        if (!config_setting_lookup_bool(route, "buffering", &globals.routes[i].buffering) && has_conv_backend("buffering", i)) {
            snprintf(config_msg, sz, "Can not find 'buffering' for router: id:%d", globals.routes[i].id);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            exit(EXIT_FAILURE);
        }
        /*
         * checking for empty data
         */

        if (0 == strcmp(globals.routes[i].router, "webhdfs") && globals.routes[i].enabled) {
            bzero(globals.active_namenode, NAME_MAX);
            snprintf(globals.active_namenode, NAME_MAX, "%s", get_active_namenode(i));
            if (NULL == globals.active_namenode || 0 == strncmp(globals.active_namenode, "(null)", 6)) {
                if (!globals.routes[i].buffering) {
                    snprintf(config_msg, sz, "Buffering is disabled as well! Nothing to do here");
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                    globals.routes[i].is_active = false;
                    snprintf(config_msg, sz, "Marking as inactive this route id[%d]", globals.routes[i].id);
                    pthread_mutex_lock(&t_error);
                    writeToCustomLog(config_msg);
                    pthread_mutex_unlock(&t_error);
                }

            } else {
                globals.routes[i].is_active = true;
            }
        }

        if (globals.workers > globals.maxcon) {
            snprintf(config_msg, sz, "Workers count can not be more than maximum connections count");
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
            globals.workers = globals.maxcon;
            snprintf(config_msg, sz, "Workers count value fixed: workers = %d", globals.workers);
            pthread_mutex_lock(&t_error);
            writeToCustomLog(config_msg);
            pthread_mutex_unlock(&t_error);
        }

    } /* for loop */


    config_destroy(cf);

    return &globals;
}

/**
 *
 */
void reconfigure() {
    readConfig(arguments.configfile);
}

char * parsePathPrefix(const char *prefix, int rc, int cc) {
    if (NULL == prefix || 0 > rc)return NULL;
    time_t rawtime;

    struct timeval t;
    char datestr[10];
    char tstamp[12];
    char timestr[8];
    char daystr[3];
    char weekstr[3];
    char monthstr[3];
    char * hostname;
    char msec[20];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    gettimeofday(&t, NULL);

    strftime(datestr, 12, "%d-%m-%Y", timeinfo);
    strftime(timestr, 8, "%H-%M", timeinfo);
    strftime(daystr, 3, "%d", timeinfo);
    strftime(monthstr, 3, "%m", timeinfo);
    strftime(weekstr, 3, "%W", timeinfo);
    snprintf(tstamp, 12, "%ld", time(NULL));

    snprintf(msec, 20, "%ld", (t.tv_usec + time(NULL)));

    if (0 != strcmp(active_connections[rc][cc].ip, "") || active_connections[rc][cc].ip == NULL) {
        hostname = active_connections[rc][cc].ip;
    } else {
        hostname = arguments.listen_host;
    }
    prefix = str_replace(prefix, "$host", hostname);
    prefix = str_replace(prefix, "$date", datestr);
    prefix = str_replace(prefix, "$time", timestr);

    prefix = str_replace(prefix, "$day", daystr);
    prefix = str_replace(prefix, "$week", weekstr);
    prefix = str_replace(prefix, "$month", monthstr);

    prefix = str_replace(prefix, "$ident", globals.identline);
    prefix = str_replace(prefix, "$tstamp", tstamp);
    prefix = str_replace(prefix, "$msec", msec);
    //

    return (char *) prefix;
}

uint32_t IPToUInt(char * ipaddr) {
    int a, b, c, d;
    uint32_t addr = 0;

    if (sscanf(ipaddr, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;

    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;

    return addr;
}

bool isIpRange(const char * range) {
    int a, b, c, d, e;
    if (sscanf(range, "%d.%d.%d.%d-%d", &a, &b, &c, &d, &e) == 5) {

        return true;
    }
    return false;
}

bool isSubnet(const char * subnet) {
    int a1, b1, c1, d1, a2, b2, c2, d2;
    if (sscanf(subnet, "%d.%d.%d.%d/%d.%d.%d.%d", &a1, &b1, &c1, &d1, &a2, &b2, &c2, &d2) == 8) {

        return true;
    }
    return false;
}

bool IsIPInRange(char * ipaddr, char * network, char * mask) {
    uint32_t ip_addr = IPToUInt(ipaddr);
    uint32_t network_addr = IPToUInt(network);
    uint32_t mask_addr = IPToUInt(mask);

    uint32_t net_lower = (network_addr & mask_addr);
    uint32_t net_upper = (net_lower | (~mask_addr));

    if (ip_addr >= net_lower && ip_addr <= net_upper) {
        return true;
    }
    return false;
}

bool isValidHostname(const char * hostname) {
    regex_t regex;
    int reti;
    bool retval = false;
    char * ValidHostnameRegex = "^([[:digit:]a-zA-Z]([-[:digit:]a-zA-Z]{0,61}[[:digit:]a-zA-Z]){0,1})$";

    reti = regcomp(&regex, ValidHostnameRegex, 0);
    if (reti) {
        retval = false;
    }
    reti = regexec(&regex, hostname, 0, NULL, 0);
    if (!reti) {
        retval = true;
    } else if (reti == REG_NOMATCH) {
        retval = false;
    }
    regfree(&regex);

    return retval;
}

/*
 *  Checking whether configuration item needs to be set.
 *  Explanation: for example , RIAK does not need the 'compressor' configuration item, therefore
 *  we do not set that setting. In this scenario the program will fail on start
 *  as it should be while some configuration item is missing unless we defined
 *  for which backend it is not allowed.
 *
 */
bool has_conv_backend(char *cf_item, int rc) {
    int module = 0, itemc;
    if (0 == strcasecmp(globals.routes[rc].router, "plain")) {
        module = 0;
    } else if (0 == strcasecmp(globals.routes[rc].router, "riak")) {
        module = 1;
    } else if (0 == strcasecmp(globals.routes[rc].router, "esearch")) {
        module = 2;
    } else if (0 == strcasecmp(globals.routes[rc].router, "webhdfs")) {
        module = 3;
    }

    for (itemc = 0; itemc < 22; itemc++) {
        if (0 == strcasecmp(cf_item, modules_cfg_allowed_keys[module][itemc])) {
            return true;
        }
    }
    return false;
}

