#define serverip          "127.0.0.1" // 服务器的地址，不支持域名
#define serverport        3478
#define clientip          "192.168.23.20/24"
#define password          "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs" // 密码固定为32位

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/wait.h>
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <arpa/inet.h>
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

struct EVENTDATALIST {
    int fd; // 目标fd
    char data[MAXDATASIZE];
    int size;
    struct EVENTDATALIST *tail;
};
struct EVENTDATALIST* evdatalisthead = NULL;
struct EVENTDATALIST* evdatalisttail;
sem_t sem;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int epollfd, clientfd;

int connect_socketfd () {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf ("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    in_addr_t ip = inet_addr(serverip); // 服务器ip地址，这里不能输入域名
    if (ip == INADDR_NONE) {
        printf ("server ip error, in %s, at %d\n", __FILE__, __LINE__);
		return -1;
    }
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons (serverport);
    if(connect (fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf ("connect server fail, in %s, at %d\n", __FILE__, __LINE__);
		return -2;
	}
    unsigned char data[37];
    data[0] = 0x10;
    memcpy (&data[1], password, 32);
    int addr = 0;
    unsigned char ipaddr = 0;
    for (int i = 0 ; i < sizeof (clientip)-1 ; i++) {
        if (clientip[i] == '.') {
            data[33+addr] = ipaddr;
            ipaddr = 0;
            addr++;
        } else if (clientip[i] == '/') {
            data[33+addr] = ipaddr;
            break;
        } else {
            ipaddr = 10 * ipaddr + (clientip[i]-'0');
        }
    }
    printf ("virtual ip:%d.%d.%d.%d, in %s, at %d\n", data[33], data[34], data[35], data[36], __FILE__, __LINE__);
    struct EVENTDATALIST* evdatalist = (struct EVENTDATALIST*) malloc (sizeof (struct EVENTDATALIST));
    if (evdatalist == NULL) {
        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    evdatalist->fd = fd;
    memcpy (evdatalist->data, data, sizeof (data));
    evdatalist->size = sizeof (data);
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
    return fd;
}

int addtoepoll (int fd) {
    struct epoll_event ev;
    memset (&ev, 0, sizeof (struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN; // 水平触发，因为每个ip数据包的大小一定小于1500，所以一定可以一次读出全部数据
    return epoll_ctl (epollfd, EPOLL_CTL_ADD, fd, &ev);
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
    sprintf (cmd, "ip address add "clientip" dev %s", ifr.ifr_name);
    system (cmd);
    sprintf (cmd, "ip link set %s up", ifr.ifr_name);
    system (cmd);
    return fd;
}

void *writethread (void *arg) {
    while (1) {
        sem_wait (&sem);
        pthread_mutex_lock (&mutex);
        struct EVENTDATALIST* evdatalist = evdatalisthead;
        evdatalisthead = evdatalisthead->tail;
        pthread_mutex_unlock (&mutex);
        char* data = evdatalist->data;
        if ((data[0] & 0xf0) == 0x40 || data[0] == 0x10 || data[0] == 0x12) { // ipv4数据包或自定义数据包
            int res = write (evdatalist->fd, evdatalist->data, evdatalist->size);
            if (res < 0) {
                exit (0);
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

void signalarmhandle () { // 发送hello包，确保数据连接还活着。
    unsigned char data[] = {0x12};
    struct EVENTDATALIST* evdatalist = (struct EVENTDATALIST*) malloc (sizeof (struct EVENTDATALIST));
    if (evdatalist == NULL) {
        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
        return;
    }
    evdatalist->fd = clientfd;
    memcpy (evdatalist->data, data, sizeof (data));
    evdatalist->size = sizeof (data);
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

int sonprocess () {
    static int tunfd;
    tunfd = tun_alloc (); // 这里使用static是因为这个变量是不会被释放的，因此将这个数据放到数据段。
    if (tunfd < 0) {
        printf ("alloc tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    clientfd = connect_socketfd ();
    if (clientfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    signal(SIGALRM, signalarmhandle);
    struct itimerval itv;
    itv.it_value.tv_sec = itv.it_interval.tv_sec = HELLOINTERVAL;
    itv.it_value.tv_usec = itv.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &itv, NULL);
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (addtoepoll (clientfd)) {
        printf ("clientfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    if (addtoepoll (tunfd)) {
        printf ("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -5;
    }
    sem_init (&sem, 0, 1);
    create_writethread ();
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait (epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            if (evs[i].events && (EPOLLERR & EPOLLHUP )) { // 检测到数据异常
                close (tunfd);
                close (clientfd);
                close (epollfd);
                printf ("receive error event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
                return -6;
            } else if (evs[i].events && EPOLLIN) {
                static char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
                int fd = evs[i].data.fd;
                int len = read (fd, readbuf, sizeof (readbuf));
                if (len < 0) {
                    close (tunfd);
                    close (clientfd);
                    close (epollfd);
                    printf ("read fail, len: %d, in %s, at %d\n", len,  __FILE__, __LINE__);
                    return -7;
                } else if (len > 0) {
                    struct EVENTDATALIST* evdatalist = (struct EVENTDATALIST*) malloc (sizeof (struct EVENTDATALIST));
                    if (evdatalist == NULL) {
                        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                        continue;
                    }
                    if (evs[i].data.fd == clientfd) {
                        evdatalist->fd = tunfd;
                    } else {
                        evdatalist->fd = clientfd;
                    }
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

int main () {
    while (1) {
        int pid = fork ();
        if (pid > 0) { // 父进程
            wait (NULL);
            sleep (2);
        } else { // 子进程
            return sonprocess ();
        }
    }
    return 0;
}
