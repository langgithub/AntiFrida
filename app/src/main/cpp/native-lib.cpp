#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <elf.h>
#include <dirent.h>
#include <ctype.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <asm/unistd.h>
#include <android/log.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "mylibc.h"
#include "raw_syscall.h"

#define MAX_LINE 512
#define MAX_LENGTH 256
//static const char *APPNAME = "DetectFrida";
const char APPNAME[] = "JNI";
// pool-frida linjector 使用frida-linjector 才会出现
static const char *FRIDA_THREAD_GUM_JS_LOOP = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR = "linjector";
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_FD = "/proc/self/fd";
static const char *PROC_TASK = "/proc/self/task";
#define LIBC "libc.so"

//Structure to hold the details of executable section of library
typedef struct stExecSection {
    int execSectionCount;
    unsigned long offset[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;


#define NUM_LIBS 2

//Include more libs as per your need, but beware of the performance bottleneck especially
//when the size of the libraries are > few MBs
static const char *libstocheck[NUM_LIBS] = {"libnative-lib.so", LIBC};
static execSection *elfSectionArr[NUM_LIBS] = {NULL};


#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#endif

static inline void parse_proc_maps_to_fetch_path(char **filepaths);

static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection);

static inline void detect_frida_loop(void *pargs);
static inline void detect_frida_loop_test();

static inline bool
scan_executable_segments(char *map, execSection *pTextSection, const char *libraryName);

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len);

static inline unsigned long checksum(void *buffer, size_t len);

static inline void detect_frida_threads();

static inline void detect_frida_namedpipe();

static inline void detect_frida_memdiskcompare();

extern "C"
JNIEXPORT jboolean Java_com_xxr0ss_antifrida_utils_AntiFrida2_checkBeingDebugged(JNIEnv *env, jobject thiz) {
    char *filePaths[NUM_LIBS];

    parse_proc_maps_to_fetch_path(filePaths);
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Libc[%x][%x][%x][%x][%x][%x]", __NR_openat,
                        __NR_lseek, __NR_read, __NR_close, __NR_readlinkat, __NR_nanosleep);
    for (int i = 0; i < NUM_LIBS; i++) {
        fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
        if (filePaths[i] != NULL)
            free(filePaths[i]);
    }
    pthread_t t;
    int status = pthread_create(&t, NULL, reinterpret_cast<void *(*)(void *)>(detect_frida_loop), NULL);
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,"pthread_create %d", status);


    pthread_t t2;
    int status2 = pthread_create(&t2, NULL, reinterpret_cast<void *(*)(void *)>(detect_frida_loop_test), NULL);
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,"pthread_create %d", status2);
    return 1;
}


__attribute__((always_inline))
static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = 0;
    char map[MAX_LINE];
    int counter = 0;
    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (my_strstr(map, libstocheck[i]) != NULL) {
                    char tmp[MAX_LENGTH] = "";
                    char path[MAX_LENGTH] = "";
                    char buf[5] = "";
                    sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                    if (buf[2] == 'x') {
                        size_t size = my_strlen(path) + 1;
                        filepaths[i] = static_cast<char*>(malloc(size));
                        my_strlcpy(filepaths[i], path, size);
                        counter++;
                    }
                }
            }
            if (counter == NUM_LIBS)
                break;
        }
        my_close(fd);
    }
}

__attribute__((always_inline))
static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {

    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd;
    int execSectionCount = 0;
    fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return NULL;
    }

    my_read(fd, &ehdr, sizeof(Elf_Ehdr));
    my_lseek(fd, (off_t) ehdr.e_shoff, SEEK_SET);

    unsigned long memsize[2] = {0};
    unsigned long offset[2] = {0};


    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));

        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

        //Typically PLT and Text Sections are executable sections which are protected
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

            offset[execSectionCount] = sectHdr.sh_offset;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) {
                break;
            }
        }
    }
    if (execSectionCount == 0) {
        __android_log_print(ANDROID_LOG_WARN, APPNAME, "No executable section found. Suspicious");
        my_close(fd);
        return false;
    }
    //This memory is not released as the checksum is checked in a thread
    *pTextSection = static_cast<execSection*>(malloc(sizeof(execSection)));

    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = static_cast<uint8_t*>(malloc(memsize[i] * sizeof(uint8_t)));
        my_read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i] = offset[i];
        (*pTextSection)->memsize[i] = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
        __android_log_print(ANDROID_LOG_WARN, APPNAME, "ExecSection:[%d][%ld][%ld][%ld]", i,
                            offset[i],
                            memsize[i], (*pTextSection)->checksum[i]);
    }

    my_close(fd);
    return true;
}


void detect_frida_bus_loop() {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton("0.0.0.0", &(sa.sin_addr));
    int sock;
    int i;
    int ret;
    char res[7];
    while(1){
        /*
         * 1:Frida Server Detection
         */
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,"entering frida server detect loop started");
        for(i=20000;i<30000;i++){
            sock = socket(AF_INET,SOCK_STREAM,0);
            sa.sin_port = htons(i);
//            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "entering frida server detect loop started,now i is %d",i);

            if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
                memset(res, 0 , 7);
                send(sock, "\x00", 1, NULL);
                send(sock, "AUTH\r\n", 6, NULL);
                usleep(500); // Give it some time to answer
                if ((ret = recv(sock, res, 6, MSG_DONTWAIT)) != -1) {
                    if (strcmp(res, "REJECT") == 0) {
                        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "FOUND FRIDA SERVER: %s,FRIDA DETECTED [1] - frida server running on port %d!",APPNAME,i);
                    }else{
                        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "not FOUND FRIDA SERVER");
                    }
                }
            }
            close(sock);
        }
        break;
    }
}

void detect_frida_loop_test() {
    struct timespec timereq;
    timereq.tv_sec = 5; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;
    while (1){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "detect_frida_loop_test");
        my_nanosleep(&timereq, NULL);
    }
}


void detect_frida_loop(void *pargs) {

    struct timespec timereq;
    timereq.tv_sec = 5; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;

    while (1) {

        // detect_frida_bus_loop();  相当于链接frida-server, 不如直接链接端口，发送的auth协议请求可能有变化
        detect_frida_threads();
        detect_frida_namedpipe();
        detect_frida_memdiskcompare();


        my_nanosleep(&timereq, NULL);

    }
}

__attribute__((always_inline))
static inline bool
scan_executable_segments(char *map, execSection *pElfSectArr, const char *libraryName) {
    unsigned long start, end;
    char buf[MAX_LINE] = "";
    char path[MAX_LENGTH] = "";
    char tmp[100] = "";

    sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Map [%s]", map);

    if (buf[2] == 'x') {
        if (buf[0] == 'r') {
            uint8_t *buffer = NULL;

            buffer = (uint8_t *) start;
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                if (start + pElfSectArr->offset[i] + pElfSectArr->memsize[i] > end) {
                    if (pElfSectArr->startAddrinMem != 0) {
                        buffer = (uint8_t *) pElfSectArr->startAddrinMem;
                        pElfSectArr->startAddrinMem = 0;
                        break;
                    }
                }
            }
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                unsigned long output = checksum(buffer + pElfSectArr->offset[i],
                                                pElfSectArr->memsize[i]);
                __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Checksum:[%ld][%ld]", output,
                                    pElfSectArr->checksum[i]);

                if (output != pElfSectArr->checksum[i]) {
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
                                        "Executable Section Manipulated, "
                                        "maybe due to Frida or other hooking framework."
                                        "Act Now!!! %s", libraryName);
                }
            }

        } else {

            char ch[10] = "", ch1[10] = "";
            __system_property_get("ro.build.version.release", ch);
            __system_property_get("ro.system.build.version.release", ch1);
            int version = my_atoi(ch);
            int version1 = my_atoi(ch1);
            if (version < 10 || version1 < 10) {
                __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Suspicious to get XOM in "
                                                                  "version < Android10");
            } else {
                if (0 == my_strncmp(libraryName, LIBC, my_strlen(LIBC))) {
                    //If it is not readable, then most likely it is not manipulated by Frida
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "LIBC Executable Section"
                                                                      " not readable! ");

                } else {
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Suspicious to get XOM "
                                                                      "for non-system library on "
                                                                      "Android 10 and above");
                }
            }
        }
        return true;
    } else {
        if (buf[0] == 'r') {
            pElfSectArr->startAddrinMem = start;
        }
    }
    return false;
}

__attribute__((always_inline))
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    my_memset(buf, 0, max_len);

    do {
        ret = my_read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}

__attribute__((always_inline))
static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *) buffer;
    size_t i;
    for (i = 0; i < len; ++i)
        seed += (unsigned long) (*buf++);
    return seed;
}

__attribute__((always_inline))
static inline void detect_frida_threads() {

    DIR *dir = opendir(PROC_TASK);

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);

            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                __android_log_print(ANDROID_LOG_INFO, APPNAME, "-----%s", buf);
                if (my_strstr(buf, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(buf, FRIDA_THREAD_GMAIN)) {
                    //Kill the thread. This freezes the app. Check if it is an anticpated behaviour
                    //int tid = my_atoi(entry->d_name);
                    //int ret = my_tgkill(getpid(), tid, SIGSTOP);
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Frida specific thread found. Act now!!!");
                }
                my_close(fd);
            }

        }
        closedir(dir);

    }

}

__attribute__((always_inline))
static inline void detect_frida_namedpipe() {

    DIR *dir = opendir(PROC_FD);
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            struct stat filestat;
            char buf[MAX_LENGTH] = "";
            char filePath[MAX_LENGTH] = "";
            snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);

            lstat(filePath, &filestat);

            if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                //TODO: Another way is to check if filepath belongs to a path not related to system or the app
                my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
                __android_log_print(ANDROID_LOG_INFO, APPNAME, "+++++++%s", buf);
                if (NULL != my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR)) {
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Frida specific named pipe found. Act now!!!");
                }
            }

        }
    }
    closedir(dir);
}

__attribute__((always_inline))
static inline void detect_frida_memdiskcompare() {
    int fd = 0;
    char map[MAX_LINE];

    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (my_strstr(map, libstocheck[i]) != NULL) {
                    if (true == scan_executable_segments(map, elfSectionArr[i], libstocheck[i])) {
                        break;
                    }
                }
            }
        }
    } else {
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "Error opening /proc/self/maps. That's usually a bad sign.");

    }
    my_close(fd);

}

