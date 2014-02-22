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

void bye() {
    writeToCustomLog("Exiting unexpectedly... Bye!");
}

bool is_valid_opt(char *opts) {
    if (opts == NULL)return false;
    if (opts[0] == '-' || opts[0] == ':' || opts[0] == '?')return false;

    return true;
}

/**
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char** argv) {

    if (0 != getuid()) {
        printf("%s", INSUFF_PRIV);
        exit(EXIT_FAILURE);
    }
    start_time = time(NULL);
    char *host = NULL;
    int opt = 0;
    int longIndex = 0;

    memset(globals.routes, 0, ROUTES_MAX_COUNT);
    //
    curl_global_init(CURL_GLOBAL_ALL);
    //
    watchdog_stop_flag = false;
    sheduler_stop_flag = false;
    pbuffer_stop_flag = false;
    rotate_stop_flag = false;
    listen_stop_flag = false;

    /* Initialize arguments before we get to work. */
    char * argument = NULL;

    argument = "/var/run/arewik.pid";
    arguments.pidfile = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.pidfile, argument);

    argument = "/var/log/arewik";
    arguments.logdir = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.logdir, argument);

    argument = "/var/arewik";
    arguments.storagedir = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.storagedir, argument);

    argument = "/var/arewik/buffers";
    arguments.bufferdir = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.bufferdir, argument);

    argument = "/etc/arewik/arewik.conf";
    arguments.configfile = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.configfile, argument);

    argument = "arewik";
    arguments.user = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.user, argument);

    argument = "arewik";
    arguments.group = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.group, argument);

    argument = "/tmp";
    arguments.wdir = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.wdir, argument);

    argument = DEFAULT_LISTEN_IP;
    arguments.listen_host = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(arguments.listen_host, argument);

    arguments.listen_port = DEFAULT_LISTEN_PORT;
    arguments.verbosity = 0;
    arguments.foreground = 0;
    arguments.debuginfo = 0;

    argument = "custom.log";
    globals.custom_logfile_name = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(globals.custom_logfile_name, argument);

    argument = "debug.log";
    globals.debug_logfile_name = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(globals.debug_logfile_name, argument);

    argument = "connections.log";
    globals.connections_logfile_name = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(globals.connections_logfile_name, argument);

    argument = "access.log";
    globals.access_logfile_name = xmalloc(sizeof (char) * strlen(argument) + 1);
    strcpy(globals.access_logfile_name, argument);

    globals.maxcon = 4096; // routes max * 64
    globals.proxymode = false; //todo
    globals.routes_cnt = 1;
    globals.watchdog_interval = WATCHDOG_T;
    globals.ping_interval = 30;
    globals.autoreconfigure = false;
    globals.reconfigure_interval = 60;
    globals.use_resolver = 0;
    globals.use_syslog = 0;
    globals.socktimeout = 10000;
    globals.epolltimeout = EPOLL_RUN_TIMEOUT;
    globals.workers = POSSIBLE_FHNDL;

    sprintf(globals.identline, "%s", ident);
    //
    globals.modules[0].id = 0;
    globals.modules[0].enabled = true;
    globals.modules[0].name = "plain";
    globals.modules[0].process_function = &process_plain;
    globals.modules[0].init_function = NULL;

    globals.modules[1].id = 1;
    globals.modules[1].enabled = false;
    globals.modules[1].name = "riak";
    globals.modules[1].process_function = &process_riak;
    globals.modules[1].init_function = &init_riak_module;
    globals.modules[1].close_function = &close_riak;

    globals.modules[2].id = 2;
    globals.modules[2].enabled = false;
    globals.modules[2].name = "esearch";
    globals.modules[2].process_function = &process_esearch;
    globals.modules[2].init_function = &init_esearch_module;
    globals.modules[2].close_function = &close_esearch;


    globals.modules[3].id = 3;
    globals.modules[3].enabled = false;
    globals.modules[3].name = "webhdfs";
    globals.modules[3].process_function = &process_webhdfs;
    globals.modules[3].init_function = &init_webhdfs_module;
    globals.modules[3].close_function = &close_webhdfs;


    CPRESS_FUNCT[0].type = SNAPPY;
    CPRESS_FUNCT[0].compress_function = &compress_snappy;

    CPRESS_FUNCT[1].type = GZIP;
    CPRESS_FUNCT[1].compress_function = &compress_gzip;


    set_sig_handler();
    static const char *optString = "s:D:B:u:g:p:l:c:H:P:vfhd?";
    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

    while (opt != -1) {
        switch (opt) {
            case 'p':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.pidfile = xrealloc(arguments.pidfile, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.pidfile, optarg);

                break;

            case 'l':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.logdir = xrealloc(arguments.pidfile, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.logdir, optarg);
                break;

            case 'c':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.configfile = xrealloc(arguments.configfile, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.configfile, optarg);
                break;

            case 'H':
                if (!isValidIP(optarg)) {
                    print_usage();
                }
                if (NULL != (host = nslookup(optarg))) {
                    arguments.listen_host = xrealloc(arguments.listen_host, (sizeof (char) * strlen(optarg) + 1));
                    strcpy(arguments.listen_host, host);
                } else {
                    printf("%s\n", hstrerror(h_errno));
                    exit(EXIT_FAILURE);
                }
                break;
            case 'u':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.user = xrealloc(arguments.user, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.user, optarg);
                break;
            case 'g':
                arguments.group = xrealloc(arguments.group, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.group, optarg);
                break;
            case 'D':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.wdir = xrealloc(arguments.wdir, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.wdir, optarg);
                break;
            case 's':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.storagedir = xrealloc(arguments.storagedir, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.storagedir, optarg);
                break;
            case 'B':
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                arguments.bufferdir = xrealloc(arguments.bufferdir, (sizeof (char) * strlen(optarg) + 1));
                strcpy(arguments.bufferdir, optarg);
                break;
            case 'P':
                arguments.listen_port = atoi(optarg);
                break;
            case 'v':
                arguments.verbosity++;
                break;
            case 'f':
                arguments.foreground++;
                break;
            case 'h':
                print_usage();
                break;
            case 'd':
                arguments.debuginfo++;
                arguments.verbosity++;
                break;
            default:
                if (!is_valid_opt(optarg)) {
                    print_usage();
                }
                break;
        }

        opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    if (false == DirectoryExists(arguments.storagedir)) {
        printf("Specified storage directory '%s' does not exists\n", arguments.storagedir);
        printf("Creating new one\n");
        if (0 > mkdir(arguments.storagedir, 0755)) {
            printf("Can not create storage directory - %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            setRightOwner(arguments.storagedir);
        }
    }
    setRightOwner(arguments.storagedir);

    if (false == DirectoryExists(arguments.bufferdir)) {
        printf("Specified buffer directory '%s' does not exists\n", arguments.bufferdir);
        printf("Creating new one\n");
        if (0 > mkdir(arguments.bufferdir, 0755)) {
            printf("Can not create buffer directory - %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            setRightOwner(arguments.bufferdir);
        }
    }
    setRightOwner(arguments.bufferdir);

    if (true == DirectoryExists(arguments.pidfile)) {
        printf("Specified pid file '%s' is a directory\n", arguments.pidfile);
        exit(EXIT_FAILURE);
    }

    if (false == DirectoryExists(arguments.wdir)) {
        printf("Specified working directory '%s' does not exists or not a directory\n", arguments.wdir);
        exit(EXIT_FAILURE);
    }

    if (arguments.foreground == 1) {
        printf("Running in foreground mode...\n");
        setbuf(stdout, 0);
        setbuf(stdin, 0);
        setbuf(stderr, 0);
    }

    if (arguments.verbosity == 1) {
        printf("Verbosity enabled\n");
    }

    if (false == FileExists(arguments.configfile)) {
        printf("Specified file '%s' does not exists\n", arguments.configfile);
        exit(EXIT_FAILURE);
    } else if (true == DirectoryExists(arguments.configfile)) {
        printf("Specified file '%s' is a directory\n", arguments.configfile);
        exit(EXIT_FAILURE);
    } else {
        setRightOwner(arguments.configfile);
        if (true != hasRightOwner(arguments.configfile)) {
            printf("The file '%s' has invalid owner/group\nMust be %s:%s\n", arguments.configfile, arguments.user, arguments.group);
            exit(EXIT_FAILURE);
        }
    }

    if (false == DirectoryExists(arguments.logdir)) {
        printf("Specified log directory '%s' does not exists\n", arguments.logdir);
        printf("Creating new one\n");
        if (0 > mkdir(arguments.logdir, 0755)) {
            printf("Can not create log directory - %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        } else {
            setRightOwner(arguments.logdir);
        }
    }
    setRightOwner(arguments.logdir);

    if (true != hasRightOwner(arguments.logdir)) {
        printf("The file '%s' has invalid owner/group\nMust be %s:%s\n", arguments.logdir, arguments.user, arguments.group);
        exit(EXIT_FAILURE);
    }


    glob = readConfig(arguments.configfile);
    checkPid();

    openCustomLog();
    openDebugLog();
    openConLog();
    openAccessLog();

    if (!(pwd = getpwnam(arguments.user))) {
        snprintf(TMP_MSG, MAXLINE, "No such user: %s. Quitting!", arguments.user);
        writeToCustomLog(TMP_MSG);

        exit(EXIT_FAILURE);
    } else my_uid = pwd->pw_uid;

    if (!(grp = getgrnam(arguments.group))) {
        snprintf(TMP_MSG, MAXLINE, "No such group: %s. Quitting!", arguments.group);
        writeToCustomLog(TMP_MSG);
        exit(EXIT_FAILURE);
    } else my_gid = grp->gr_gid;

    if (arguments.foreground == 0) {

        pid = fork();

        if (pid < 0) {
            snprintf(TMP_MSG, MAXLINE, "%s", "Can not fork! [Invalid PID]");
            writeToCustomLog(TMP_MSG);
            removePid();
            exit(EXIT_FAILURE);
        }
        /* If we got a good PID, then
           we can exit the parent process. */
        if (pid > 0) {
            exit(EXIT_SUCCESS);
        }
        //
        snprintf(TMP_MSG, MAXLINE, "%s", "Forked successfully");
        writeToCustomLog(TMP_MSG);
        /* Change the file mode mask */
        umask(027);
        /* Create a new SID for the child process */
        sid = setsid();
        if (sid < 0) {
            snprintf(TMP_MSG, MAXLINE, "%s", "Can not create child process");
            writeToCustomLog(TMP_MSG);
            /* Log the failure */
            removePid();
            exit(EXIT_FAILURE);
        }
        snprintf(TMP_MSG, MAXLINE, "%s", "Daemonizing");
        writeToCustomLog(TMP_MSG);

        /* Change the current working directory */
        if ((chdir(arguments.wdir)) < 0) {
            snprintf(TMP_MSG, MAXLINE, "%s", "Can not change current directory");
            writeToCustomLog(TMP_MSG);
            /* Log the failure */
            exit(EXIT_FAILURE);
        }
        snprintf(TMP_MSG, MAXLINE, "%s", "Working directory changed");
        writeToCustomLog(TMP_MSG);
    }
    savePid();

    if ((setgid(my_gid)) < 0) {
        snprintf(TMP_MSG, MAXLINE, "ERROR: setgid(%d) failed: %s", my_gid, strerror(errno));
        writeToCustomLog(TMP_MSG);
        halt();
    }
    snprintf(TMP_MSG, MAXLINE, "Group ID changed to %d", my_gid);
    writeToCustomLog(TMP_MSG);

    if ((setuid(my_uid)) < 0) {
        snprintf(TMP_MSG, MAXLINE, "ERROR: setuid(%d) failed: %s", my_uid, strerror(errno));
        writeToCustomLog(TMP_MSG);
        halt();
    }
    snprintf(TMP_MSG, MAXLINE, "User ID changed to %d", my_gid);
    writeToCustomLog(TMP_MSG);


    if (arguments.foreground == 0) {
        snprintf(TMP_MSG, MAXLINE, "%s", "Closing descriptors & disabling verbosity.\nEnsure you have set right permissions for your log file.\nWatch your log file for further information\n");
        VERBOSE(TMP_MSG);
        arguments.verbosity = 0;
        /* Close out the standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }
    ////////////////////////////////////////////////////////////////////////////////

    //
    init_arrays();

    init_webhdfs_arrays();

    init_active_c_table();
    init_descriptors();
    scan_connections();
    //
    ////////////////////////////////////////////////////////////////////////////////
    spawn_threads();
    do_listen();

    ////////////////////////////////////////////////////////////////////////////////
    /* This never happens */
    return 0;
}

