#define serverip          "192.168.56.101" // 服务器的地址，不支持域名
#define serverport        3480
#define password          "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs" // 密码固定为32位

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
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

#define MAXDATASIZE       2*1024*1024
#define MAX_EVENT         1024
#define MTU_SIZE          1500
#define KEEPALIVE            // 如果定义了，就是启动心跳包，不定义就不启动，下面3个参数就没有意义。
#define KEEPIDLE          60 // tcp完全没有数据传输的最长间隔为60s，操过60s就要发送询问数据包
#define KEEPINTVL         5  // 如果询问失败，间隔多久再次发出询问数据包
#define KEEPCNT           3  // 如果询问失败，间隔多久再次发出询问数据包
#define RETRYINTERVAL     5  // 如果重要链接断掉了，重连间隔时间，单位秒

struct PACKAGELIST {
    unsigned char data[MTU_SIZE + 18];
    int32_t size;
    struct PACKAGELIST *tail;
};
struct PACKAGELIST *remainpackagelisthead = NULL;
struct CLIENTLIST {
    int fd; // 与fdclient中的fd意义一样，只是为了方便使用而已
    struct PACKAGELIST *packagelisthead; // 发给自己这个端口的数据包列表头部
    struct PACKAGELIST *packagelisttail; // 发给自己这个端口的数据包列表尾部
    unsigned char remainpackage[MTU_SIZE + 18]; // 自己接收到的数据出现数据不全，将不全的数据存在这里，等待新的数据将其补全
    int remainsize; // 不全的数据大小
    int canwrite;
} tclient, sclient;
struct CLIENTLIST *tapclient = &tclient;
struct CLIENTLIST *socketclient = &sclient;
int epollfd;

int setnonblocking (int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        printf("get flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("set flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    return 0;
}

int addtoepoll (struct CLIENTLIST *fdclient) {
    struct epoll_event ev;
    ev.data.ptr = fdclient;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fdclient->fd, &ev);
}

int modepoll (struct CLIENTLIST *client, int flags) {
    struct epoll_event ev;
    ev.data.ptr = client;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP | flags; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_MOD, client->fd, &ev);
}

int writenode (struct CLIENTLIST *client) {
    struct PACKAGELIST *package = client->packagelisthead;
    client->packagelisthead = NULL;
    while (package != NULL) {
        ssize_t len = write(client->fd, package->data, package->size);
        if (len < package->size) { // 缓冲区不足，已无法继续写入数据。
            if (len < 0) {
                if (client == tapclient) {
                    perror("tap write error");
                } else {
                    perror("socket write error");
                }
                client->packagelisthead = package;
                break;
            }
            int32_t size = package->size - len;
            unsigned char tmpdata[MTU_SIZE + 18];
            memcpy(tmpdata, package->data + len, size);
            memcpy(package->data, tmpdata, size);
            package->size = size;
            client->packagelisthead = package;
            if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                if (modepoll(client, EPOLLOUT)) { // 监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    break;
                }
                client->canwrite = 0;
            }
            break;
        } else if (client->canwrite == 0) { // 缓冲区尚有空间，并且之前已经提示不足
            if (modepoll(client, 0)) { // 取消监听可写事件
                printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                break;
            }
            client->canwrite = 1;
        }
        struct PACKAGELIST *tmppackage = package;
        package = package->tail;
        tmppackage->tail = remainpackagelisthead;
        remainpackagelisthead = tmppackage;
    }
    return 0;
}

int readdata (struct CLIENTLIST *client) {
    static unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    static unsigned char *readbuff = NULL; // 这里是用于存储全部的需要写入的数据buf，
    static int32_t maxtotalsize = 0;
    ssize_t len;
    int fd = client->fd;
    struct CLIENTLIST *targetclient;
    if (client == tapclient) { // tap驱动，原始数据，需要自己额外添加数据包长度。
        len = read(fd, readbuf + 2, MAXDATASIZE); // 这里最大只可能是1518
        if (len < 0) {
            perror("tap read error");
            return -1;
        }
        readbuf[0] = len >> 8;
        readbuf[1] = len & 0xff;
        len += 2;
        targetclient = socketclient;
    } else { // 网络套接字。
        len = read(fd, readbuf, MAXDATASIZE);
        if (len < 0) {
            perror("socket read error");
            return -2;
        }
        targetclient = tapclient;
    }
    int32_t offset = 0;
    int32_t totalsize;
    unsigned char *buff;
    if (client->remainsize > 0) {
        totalsize = client->remainsize + len;
        if (totalsize > maxtotalsize) {
            maxtotalsize = totalsize;
            if (readbuff != NULL) {
                free (readbuff);
            }
            readbuff = (unsigned char*) malloc(totalsize * sizeof(unsigned char));
            if (readbuff == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -3;
            }
        }
        memcpy(readbuff, client->remainpackage, client->remainsize);
        memcpy(readbuff + client->remainsize, readbuf, len);
        client->remainsize = 0;
        buff = readbuff;
    } else {
        totalsize = len;
        buff = readbuf;
    }
    struct CLIENTLIST *writeclient = NULL;
    while (offset < totalsize) {
        if (offset + 64 > totalsize) { // mac帧单个最小必须是64个，小于这个的数据包一定不完整
            int32_t remainsize = totalsize - offset;
            memcpy(client->remainpackage, buff + offset, remainsize);
            client->remainsize = remainsize;
            break;
        }
        int32_t packagesize = 256*buff[offset] + buff[offset+1] + 2; // 当前数据帧大小
        if (offset + packagesize > totalsize) {
            int32_t remainsize = totalsize - offset;
            memcpy(client->remainpackage, buff + offset, remainsize);
            client->remainsize = remainsize;
            break;
        }
        struct PACKAGELIST *package;
        if (remainpackagelisthead != NULL) { // 全局数据包回收站不为空
            package = remainpackagelisthead;
            remainpackagelisthead = remainpackagelisthead->tail;
        } else {
            package = (struct PACKAGELIST*) malloc(sizeof(struct PACKAGELIST));
            if (package == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                offset += packagesize;
                continue;
            }
        }
        if (client == tapclient) {
            memcpy(package->data, buff + offset, packagesize);
            package->size = packagesize;
        } else {
            memcpy(package->data, buff + offset + 2, packagesize);
            package->size = packagesize - 2;
        }
        package->tail = NULL;
        if (targetclient->packagelisthead == NULL) {
            targetclient->packagelisthead = package;
            targetclient->packagelisttail = targetclient->packagelisthead;
        } else {
            targetclient->packagelisttail->tail = package;
            targetclient->packagelisttail = targetclient->packagelisttail->tail;
        }
        offset += packagesize;
    }
    if (targetclient->canwrite) {
        writenode(targetclient);
    }
    return 0;
}

int tap_alloc () {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        printf("open tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, (void*) &ifr) < 0) {
        printf("ioctl tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    if (setnonblocking(fd) < 0) {
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    printf("tap device name is %s, in %s, at %d\n", ifr.ifr_name, __FILE__, __LINE__);
    tapclient->fd = fd;
    tapclient->packagelisthead = NULL;
    tapclient->remainsize = 0;
    tapclient->canwrite = 1;
    if (addtoepoll(tapclient)) {
        printf("clientfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    return 0;
}

int connect_socketfd (unsigned char *ip, unsigned int port) {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    in_addr_t _ip = inet_addr(ip); // 服务器ip地址，这里不能输入域名
    if (_ip == INADDR_NONE) {
        printf("server ip error, in %s, at %d\n", __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    sin.sin_addr.s_addr = _ip;
    sin.sin_port = htons(port);
    if(connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("connect server fail, in %s, at %d\n", __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    unsigned char data[3+sizeof(password)-1];
    memset(data, 0, 3);
    memcpy(data + 3, password, sizeof(password)-1);
    write(fd, data, sizeof(data));
    if (setnonblocking(fd) < 0) { // 设置为非阻塞IO
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    unsigned int socksval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (unsigned char*)&socksval, sizeof(socksval))) { // 关闭Nagle协议
        printf("close Nagle protocol fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -5;
    }
#ifdef KEEPALIVE
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (unsigned char*)&socksval, sizeof(socksval))) { // 启动tcp心跳包
        printf("set socket keepalive fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -6;
    }
    socksval = KEEPIDLE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepidle fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -7;
    }
    socksval = KEEPINTVL;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepintvl fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -8;
    }
    socksval = KEEPCNT;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepcnt fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -9;
    }
#endif
    // 修改发送缓冲区大小
    socklen_t socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -10;
    }
    printf("old send buffer is %d, socksval_len:%d, in %s, at %d\n", socksval, socksval_len,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof(socksval))) {
        printf("set send buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -11;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -12;
    }
    printf("new send buffer is %d, socksval_len:%d, in %s, at %d\n", socksval, socksval_len,  __FILE__, __LINE__);
    // 修改接收缓冲区大小
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -13;
    }
    printf("old receive buffer is %d, len:%d, in %s, at %d\n", socksval, socksval_len,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, sizeof(socksval))) {
        printf("set receive buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -14;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -15;
    }
    printf("new receive buffer is %d, socksval_len:%d, in %s, at %d\n", socksval, socksval_len,  __FILE__, __LINE__);
    socketclient->fd = fd;
    socketclient->packagelisthead = NULL;
    socketclient->remainsize = 0;
    socketclient->canwrite = 1;
    if (addtoepoll(socketclient)) {
        printf("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -16;
    }
    return 0;
}

int removeclient (struct CLIENTLIST *client) {
    struct epoll_event ev;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, client->fd, &ev);
    close(client->fd);
    for (struct PACKAGELIST *package = client->packagelisthead ; package != NULL ; package = package->tail) {
        package->tail = remainpackagelisthead;
        remainpackagelisthead = package;
    }
    if (client == socketclient) { // 常规情况
        do {
            sleep(RETRYINTERVAL);
            printf("try connect tcp socket again, in %s, at %d\n", __FILE__, __LINE__);
        }
        while (connect_socketfd(serverip, serverport));
    } else { // 基本不可能情况
        do {
            sleep(RETRYINTERVAL);
            printf("try connect tap driver again, in %s, at %d\n", __FILE__, __LINE__);
        }
        while (tap_alloc());
    }
    return 0;
}

int main () {
    epollfd = epoll_create(MAX_EVENT);
    if (epollfd < 0) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    if (tap_alloc()) {
        printf("alloc tap fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    if (connect_socketfd(serverip, serverport)) {
        printf("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait(epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            struct CLIENTLIST *client = evs[i].data.ptr;
            uint32_t events = evs[i].events;
            if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                printf ("receive error event, fd:%d, EPOLLERR:%d, EPOLLHUP:%d, EPOLLRDHUP:%d, in %s, at %d\n", client->fd, events&EPOLLERR ? 1 : 0, events&EPOLLHUP ? 1 : 0, events&EPOLLRDHUP ? 1 : 0,  __FILE__, __LINE__);
                removeclient(client);
            } else if (events & EPOLLIN) {
                if (readdata(client)) {
                    removeclient(client);
                }
            } else if (events & EPOLLOUT) {
                writenode(client);
            } else {
                printf("receive new event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
