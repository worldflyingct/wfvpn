#define tundevip          "192.168.23.1/24"
#define serverport        3478
#define password          "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs" // 密码固定为32位

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <netinet/in.h>
#include <sys/epoll.h>
// 包入线程相关的头部
#include <pthread.h>
#include <semaphore.h>
// 定时器相关
#include <sys/time.h>

#define MAXDATASIZE       2048
#define MAXTHREAD         1
#define MAX_EVENT         64
#define MAX_ACCEPT        64
#define HELLOINTERVAL     5

struct CLIENTLIST {
    int fd;
    unsigned char ip[4];
    int watchdog;
    struct CLIENTLIST *head;
    struct CLIENTLIST *tail;
};
struct CLIENTLIST* clientlisthead = NULL;
struct CLIENTLIST* clientlisttail;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
struct EVENTDATALIST {
    int fd; // 发送这个数据报过来的fd
    char data[MAXDATASIZE];
    int size;
    struct EVENTDATALIST *tail;
};
struct EVENTDATALIST* evdatalisthead = NULL;
struct EVENTDATALIST* evdatalisttail;
sem_t sem;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int epollfd, tunfd, serverfd;

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

int addtoepoll (int fd) {
    struct epoll_event ev;
    memset (&ev, 0, sizeof (struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN; // 水平触发，因为每个ip数据包的大小一定小于1500，所以一定可以一次读出全部数据
    return epoll_ctl (epollfd, EPOLL_CTL_ADD, fd, &ev);
}

int removeclient (int fd) {
    struct EVENTDATALIST* evdatalist = (struct EVENTDATALIST*) malloc (sizeof (struct EVENTDATALIST));
    if (evdatalist == NULL) {
        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    evdatalist->fd = fd;
    evdatalist->data[0] = 0x11;
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
    return 0;
}

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
    printf ("tun ip is "tundevip", in %s, at %d\n", __FILE__, __LINE__);
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
    clientlisthead->watchdog = -1;
    clientlisthead->head = NULL;
    clientlisthead->tail = NULL;
    clientlisttail = clientlisthead;
    return fd;
}

void *writethread (void *arg) {
    while (1) {
        sem_wait (&sem);
        pthread_mutex_lock (&mutex);
        struct EVENTDATALIST* evdatalist = evdatalisthead;
        evdatalisthead = evdatalisthead->tail;
        pthread_mutex_unlock (&mutex);
        unsigned char* data = evdatalist->data;
        if ((data[0] & 0xf0) == 0x40) { // ipv4数据包
            unsigned char ip[4];
            memcpy(ip, &data[16], 4);
            int fd = 0;
            pthread_rwlock_rdlock (&rwlock);
            for (struct CLIENTLIST* clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (ip[0] == clientlist->ip[0] && ip[1] == clientlist->ip[1] && ip[2] == clientlist->ip[2] && ip[3] == clientlist->ip[3]) {
                    fd = clientlist->fd;
                    break;
                }
            }
            pthread_rwlock_unlock (&rwlock);
            if (fd) { // 如果fd不为0，就说明找到了对应的连接
                int res = write (fd, evdatalist->data, evdatalist->size);
                if (res < 0) {
                    removeclient (fd);
                }
            }
        } else if (data[0] == 0x10) { // 自定义的绑定用数据包
            if (memcmp (&data[1], password, 32)) { // 绑定密码错误
                struct epoll_event ev;
                epoll_ctl (epollfd, EPOLL_CTL_DEL, evdatalist->fd, &ev);
                close (evdatalist->fd);
                printf ("password fail, in %s, at %d\n",  __FILE__, __LINE__);
            } else { // 绑定密码正确
                unsigned char ip[4];
                memcpy(ip, &data[33], 4);
                int canuse = 1;
                pthread_rwlock_rdlock (&rwlock);
                for (struct CLIENTLIST* clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                    if (ip[0] == clientlist->ip[0] && ip[1] == clientlist->ip[1] && ip[2] == clientlist->ip[2] && ip[3] == clientlist->ip[3]) {
                        canuse = 0;
                        break;
                    }
                }
                pthread_rwlock_unlock (&rwlock);
                if (canuse) { // ip可用
                    struct CLIENTLIST* clientlist = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
                    if (clientlist == NULL) {
                        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                    } else {
                        clientlist->fd = evdatalist->fd;
                        memcpy (clientlist->ip, ip, 4);
                        clientlist->watchdog = 3;
                        clientlist->tail = NULL;
                        pthread_rwlock_wrlock (&rwlock);
                        clientlist->head = clientlisttail;
                        clientlisttail->tail = clientlist;
                        clientlisttail = clientlisttail->tail;
                        pthread_rwlock_unlock (&rwlock);
                        printf ("add client success, client ip is %d.%d.%d.%d, in %s, at %d\n", ip[0], ip[1], ip[2], ip[3],  __FILE__, __LINE__);
                    }
                } else { // ip已经被占用
                    printf ("ip %d.%d.%d.%d is used, in %s, at %d\n", ip[0], ip[1], ip[2], ip[3],  __FILE__, __LINE__);
                    struct epoll_event ev;
                    epoll_ctl (epollfd, EPOLL_CTL_DEL , evdatalist->fd, &ev);
                    close (evdatalist->fd);
                }
            }
        } else if (data[0] == 0x11) { // 自定义的从用户列表中删除
            struct epoll_event ev;
            epoll_ctl (epollfd, EPOLL_CTL_DEL , evdatalist->fd, &ev);
            close (evdatalist->fd);
            pthread_rwlock_wrlock (&rwlock);
            struct CLIENTLIST* clientlist;
            for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (clientlist->fd == evdatalist->fd) {
                    printf ("host %d.%d.%d.%d disconnect, in %s, at %d\n", clientlist->ip[0], clientlist->ip[1], clientlist->ip[2], clientlist->ip[3],  __FILE__, __LINE__);
                    if (clientlist->head == NULL) {
                        clientlisthead = clientlist->tail;
                        clientlisthead->head = NULL;
                    } else if (clientlist->tail == NULL) {
                        clientlisttail = clientlist->head;
                        clientlisttail->tail = NULL;
                    } else {
                        clientlist->head->tail = clientlist->tail;
                        clientlist->tail->head = clientlist->head;
                    }
                    break;
                }
            }
            pthread_rwlock_unlock (&rwlock);
            if (clientlist != NULL) {
                free (clientlist);
            }
        } else if (data[0] == 0x12) { // 自定义的hello包
            pthread_rwlock_rdlock (&rwlock);
            for (struct CLIENTLIST* clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (clientlist->fd == evdatalist->fd) {
                    clientlist->watchdog = 3;
                    break;
                }
            }
            pthread_rwlock_unlock (&rwlock);
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

void signalarmhandle () { // hello包检查，超过3
    pthread_rwlock_rdlock (&rwlock);
    for (struct CLIENTLIST* clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
        if (clientlist->fd == tunfd) {
            continue;
        }
        clientlist->watchdog--;
        if (clientlist->watchdog == 0) {
            printf ("socket timeout, in %s, at %d\n",  __FILE__, __LINE__);
            removeclient (clientlist->fd);
        }
    }
    pthread_rwlock_unlock (&rwlock);
}

int main () {
    tunfd = tun_alloc (); // 这里使用static是因为这个变量是不会被释放的，因此将这个数据放到数据段。
    if (tunfd < 0) {
        printf ("alloc tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    serverfd = create_socketfd ();
    if (serverfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    signal (SIGALRM, signalarmhandle);
    struct itimerval itv;
    itv.it_value.tv_sec = itv.it_interval.tv_sec = HELLOINTERVAL;
    itv.it_value.tv_usec = itv.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &itv, NULL);
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (addtoepoll (serverfd)) {
        printf ("serverfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    if (addtoepoll (tunfd)) {
        printf ("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -5;
    }
    sem_init (&sem, 0, 0);
    create_writethread ();
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait (epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            if (evs[i].events && (EPOLLERR & EPOLLHUP )) { // 检测到数据异常
                printf ("connect lose, in %s, at %d\n",  __FILE__, __LINE__);
                removeclient (evs[i].data.fd);
                continue;
            } else if (evs[i].data.fd == serverfd) {
                printf ("new socket, in %s, at %d\n",  __FILE__, __LINE__);
                struct sockaddr_in sin;
                socklen_t in_addr_len = sizeof (struct sockaddr_in);
                int newfd = accept (serverfd, (struct sockaddr*)&sin, &in_addr_len);
                if (newfd < 0) {
                    printf ("accept a new fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                if (addtoepoll (newfd)) {
                    close (newfd);
                    printf ("addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
            } else if (evs[i].events && EPOLLIN) {
                static char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
                int fd = evs[i].data.fd;
                int len = read (fd, readbuf, sizeof (readbuf));
                if (len < 0) {
                    printf ("read fail, len: %d, in %s, at %d\n", len,  __FILE__, __LINE__);
                    removeclient (fd);
                } else if (len > 0) {
                    struct EVENTDATALIST* evdatalist = (struct EVENTDATALIST*) malloc (sizeof (struct EVENTDATALIST));
                    if (evdatalist == NULL) {
                        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                        continue;
                    }
                    evdatalist->fd = fd;
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
                printf ("receive new event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
