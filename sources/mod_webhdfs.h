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

#ifndef WEBHDFS_H
#define	WEBHDFS_H

#ifdef	__cplusplus
extern "C" {
#endif
#define KB 1024UL
#define MB 1024UL * KB
#define GB 1024UL * MB
#define TB 1024UL * GB

#define WEBHDFS_ROOT "/webhdfs/v1/"
#define CTIMEOUT 10
#define UPLOAD_DATA_BUF_LIMIT (20 * MB)
#define HALT_ON_IERROR_C 10
#define REMOTE_FILE_CATTEMPTS 3

    char * temps = NULL;
    FILE * tempfd = NULL;

    char tmp_buf[ROUTES_MAX_COUNT][MAX_CON_PER_ROUTER][NAME_MAX]; // temporary buffer file name storage 

    struct _active_node {
        int is_active;
    };


#ifdef	__cplusplus
}
#endif

#endif	/* WEBHDFS_H */

