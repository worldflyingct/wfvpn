#define tundevip          "192.168.23.1/24"
#define serverport        3478
#define password          "uXdm1o9Uq4m0aMm3"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <netinet/in.h>
#include <sys/epoll.h>
// 包入线程相关的头部
#include <pthread.h>
#include <semaphore.h>

#define MAXDATASIZE       2048
#define MAXTHREAD         1
#define MAX_EVENT         64
#define MAX_ACCEPT        16

int create_socketfd () {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf ("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    sin.sin_addr.s_addr = INADDR_ANY; // 本机任意ip
    sin.sin_port = htons (serverport);
    if (bind (fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf ("bind port %d fail, in %s, at %d\n", serverport, __FILE__, __LINE__);
        return -2;
    }
    if (listen (fd, MAX_EVENT) < 0) {
        printf ("listen port %d fail, in %s, at %d\n", serverport, __FILE__, __LINE__);
        return -3;
    }
    return fd;
}

int addtoepoll (int epollfd, int fd) {
    struct epoll_event ev;
    memset (&ev, 0, sizeof (struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN; // 水平触发，因为每个ip数据包的大小一定小于1500，所以一定可以一次读出全部数据
    return epoll_ctl (epollfd, EPOLL_CTL_ADD, fd, &ev);
}

int removetoepoll (int epollfd, int fd) {
    struct epoll_event ev;
    return epoll_ctl (epollfd, EPOLL_CTL_DEL , fd, &ev);
}

struct CLIENTLIST {
    int fd;
    unsigned char ip[4];
    struct CLIENTLIST *head;
    struct CLIENTLIST *tail;
};
struct CLIENTLIST* clientlisthead = NULL;
struct CLIENTLIST* clientlisttail;

int tun_alloc () {
    int fd = open ("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        printf ("open tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0) {
        printf ("ioctl tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        close (fd);
        return -2;
    }
    printf ("tun device name is %s, in %s, at %d\n", ifr.ifr_name, __FILE__, __LINE__);
    char cmd [128];
    sprintf (cmd, "ip address add "tundevip" dev %s", ifr.ifr_name);
    system (cmd);
    sprintf (cmd, "ip link set %s up", ifr.ifr_name);
    system (cmd);
    clientlisthead = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
    if (clientlisthead == NULL) {
        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    clientlisthead->fd = fd;
    int addr = 0;
    unsigned char ipaddr = 0;
    for (int i = 0 ; i < sizeof (tundevip)-1 ; i++) {
        if (tundevip[i] == '.') {
            clientlisthead->ip[addr] = ipaddr;
            ipaddr = 0;
            addr++;
        } else if (tundevip[i] == '/') {
            clientlisthead->ip[addr] = ipaddr;
            break;
        } else {
            ipaddr = 10 * ipaddr + (tundevip[i]-'0');
        }
    }
    clientlisthead->head = NULL;
    clientlisthead->tail = NULL;
    clientlisttail = clientlisthead;
    return fd;
}

struct EVENTDATALIST {
    int fd; // 发送这个数据报过来的fd
    char data[MAXDATASIZE];
    int size;
    struct EVENTDATALIST *tail;
};
struct EVENTDATALIST* evdatalisthead = NULL;
struct EVENTDATALIST* evdatalisttail;
int tunfd, serverfd, epollfd;
sem_t sem;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *writethread (void *arg) {
    while (1) {
        sem_wait (&sem);
        pthread_mutex_lock (&mutex);
        struct EVENTDATALIST* evdatalist = evdatalisthead;
        evdatalisthead = evdatalisthead->tail;
        pthread_mutex_unlock (&mutex);
        char* data = evdatalist->data;
        if ((data[0] & 0xf0) == 0x40) { // ipv4数据包
            unsigned char ip[4];
            memcpy(ip, &data[16], 4);
            struct CLIENTLIST* clientlist = clientlisthead;
            while (clientlist != NULL) {
                if (ip[0] == clientlist->ip[0] && ip[1] == clientlist->ip[1] && ip[2] == clientlist->ip[2] && ip[3] == clientlist->ip[3]) {
                    write (clientlist->fd, evdatalist->data, evdatalist->size);
                    break;
                }
                clientlist = clientlist->tail;
            }
        } else if ((data[0] & 0xf0) == 0x10) { // 自定义的绑定用数据包
            if (memcmp (&data[1], password, 16)) { // 绑定密码错误
                removetoepoll (epollfd, evdatalist->fd);
                close (evdatalist->fd);
                printf ("password fail, in %s, at %d\n",  __FILE__, __LINE__);
            } else { // 绑定密码正确
                unsigned char ip[4];
                memcpy(ip, &data[17], 4);
                int canuse = 1;
                struct CLIENTLIST* clientlist = clientlisthead;
                while (clientlist != NULL) {
                    if (ip[0] == clientlist->ip[0] && ip[1] == clientlist->ip[1] && ip[2] == clientlist->ip[2] && ip[3] == clientlist->ip[3]) {
                        canuse = 0;
                        break;
                    }
                    clientlist = clientlist->tail;
                }
                if (canuse) { // ip可用
                    struct CLIENTLIST* clh = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
                    if (clh == NULL) {
                        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                    } else {
                        clh->fd = evdatalist->fd;
                        memcpy (clh->ip, ip, 4);
                        clh->tail = NULL;
                        clh->head = clientlisttail;
                        clientlisttail->tail = clh;
                        clientlisttail = clientlisttail->tail;
                    }
                } else { // ip已经被占用
                    removetoepoll (epollfd, evdatalist->fd);
                    close (evdatalist->fd);
                }
            }
        }
        free (evdatalist);
    }
}

int create_writethread () {
    for (int i = 0 ; i < MAXTHREAD ; i++) {
        pthread_t threadid;
        pthread_attr_t attr;
        pthread_attr_init (&attr);
        pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
        pthread_create (&threadid, &attr, writethread, NULL);
        pthread_attr_destroy (&attr);
    }
}

struct epoll_event evs[MAX_EVENT];
char readbuf[MAXDATASIZE];
int wait_count, n;

int main () {
    tunfd = tun_alloc ();
    if (tunfd < 0) {
        printf ("alloc tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    serverfd = create_socketfd ();
    if (serverfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (addtoepoll (epollfd, serverfd)) {
        printf ("serverfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    if (addtoepoll (epollfd, tunfd)) {
        printf ("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    create_writethread ();
    sem_init (&sem, 0, 0);
    while (1) {
        wait_count = epoll_wait (epollfd, evs, MAX_EVENT, -1);
        for (n = 0 ; n < wait_count ; n++) {
            if (evs[n].events && (EPOLLERR & EPOLLHUP )) { // 检测到数据异常
                removetoepoll (epollfd, evs[n].data.fd);
                close (evs[n].data.fd);
                continue;
            } else if (evs[n].data.fd == serverfd) {
                struct sockaddr_in sin;
                socklen_t in_addr_len = sizeof (struct sockaddr_in);
                int newfd = accept (serverfd, (struct sockaddr*)&sin, &in_addr_len);
                if (newfd < 0) {
                    printf ("accept a new fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                if (addtoepoll (epollfd, newfd)) {
                    close (newfd);
                    printf ("addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
            } else if (evs[n].events && EPOLLIN) {
                int len = read (evs[n].data.fd, readbuf, sizeof (readbuf));
                if (len < 0) {
                    printf ("read fail, len: %d, in %s, at %d\n", len,  __FILE__, __LINE__);
                    removetoepoll (epollfd, evs[n].data.fd);
                    close (evs[n].data.fd);
                } else if (len > 0) {
                    struct EVENTDATALIST* evdatalist = (struct EVENTDATALIST*) malloc (sizeof (struct EVENTDATALIST));
                    if (evdatalist == NULL) {
                        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                        continue;
                    }
                    evdatalist->fd = evs[n].data.fd;
                    memcpy (evdatalist->data, readbuf, len);
                    evdatalist->size = len;
                    evdatalist->tail = NULL;
                    pthread_mutex_lock (&mutex);
                    if (evdatalisthead == NULL) {
                        evdatalisthead = evdatalist;
                        evdatalisttail = evdatalisthead;
                    } else {
                        evdatalisttail->tail = evdatalist;
                        evdatalisttail = evdatalisttail->tail;
                    }
                    pthread_mutex_unlock (&mutex);
                    sem_post(&sem);
                }
            } else {
                printf ("receive new event 0x%08x, in %s, at %d\n", evs[n].events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
