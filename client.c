#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

#define MAXDATASIZE       2*1024*1024
#define MAX_EVENT         1024
#define MTU_SIZE          1500
#define KEEPALIVE            // 如果定义了，就是启动心跳包，不定义就不启动，下面3个参数就没有意义。
#define KEEPIDLE          60 // tcp完全没有数据传输的最长间隔为60s，操过60s就要发送询问数据包
#define KEEPINTVL         3  // 如果询问失败，间隔多久再次发出询问数据包
#define KEEPCNT           1  // 连续多少次失败断开连接
#define SUPPORTDOMAIN        // 支持域名访问服务器
// #define USETLS               // 使用TLS加密

#ifdef   USETLS
#include <openssl/ssl.h>
SSL_CTX *ctx;
#endif

struct PACKAGELIST {
    unsigned char data[MTU_SIZE + 18];
    int size;
    struct PACKAGELIST *tail;
};
struct PACKAGELIST *remainpackagelisthead = NULL;
struct CLIENTLIST {
    int fd;
#ifdef   USETLS
    SSL *tls;
#endif
    struct PACKAGELIST *packagelisthead; // 发给自己这个端口的数据包列表头部
    struct PACKAGELIST *packagelisttail; // 发给自己这个端口的数据包列表尾部
    unsigned char remainpackage[MTU_SIZE + 18]; // 自己接收到的数据出现数据不全，将不全的数据存在这里，等待新的数据将其补全
    unsigned int remainsize; // 不全的数据大小
    int canwrite;
} tclient, sclient;
struct CLIENTLIST *tapclient = &tclient;
struct CLIENTLIST *socketclient = &sclient;
int epollfd;

unsigned char serverip[256]; // 服务器的地址
unsigned int serverport; // 服务器的连接端口
unsigned char password[33]; // 密码固定为32位
unsigned char retryinterval; // 恢复时间

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
#ifdef   USETLS
    tapclient->tls = NULL;
#endif
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

int connect_socketfd (unsigned char *host, unsigned int port) {
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    printf("host:%s, port:%d, in %s, at %d\n", host, port, __FILE__, __LINE__);
    sin.sin_family = AF_INET; // ipv4
#ifdef SUPPORTDOMAIN
    struct hostent *ip = gethostbyname(host); // 域名dns解析
    if(ip == NULL) {
        printf("get ip by domain error, domain:%s, in %s, at %d\n", host,  __FILE__, __LINE__);
        return -1;
    }
    unsigned char *addr = ip->h_addr_list[0];
    if (ip->h_addrtype == AF_INET) { // ipv4
        memcpy(&sin.sin_addr.s_addr, addr, 4);
    } else if (ip->h_addrtype == AF_INET6) { // ipv6
        printf("not support ipv6, in %s, at %d\n", host, port, __FILE__, __LINE__);
        return -2;
    }
#else
    in_addr_t _ip = inet_addr(host); // 服务器ip地址，这里不能输入域名
    if (_ip == INADDR_NONE) {
        printf("server ip error, ip:%s, fd:%d, in %s, at %d\n", ip, fd, __FILE__, __LINE__);
        return -3;
    }
    sin.sin_addr.s_addr = _ip;
#endif
    sin.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("run socket function is fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -4;
    }
    if(connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("connect server fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -5;
    }
    unsigned int socksval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (unsigned char*)&socksval, sizeof(socksval))) { // 关闭Nagle协议
        printf("close Nagle protocol fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -6;
    }
#ifdef KEEPALIVE
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (unsigned char*)&socksval, sizeof(socksval))) { // 启动tcp心跳包
        printf("set socket keepalive fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -7;
    }
    socksval = KEEPIDLE;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepidle fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -8;
    }
    socksval = KEEPINTVL;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepintvl fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -9;
    }
    socksval = KEEPCNT;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepcnt fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -10;
    }
#endif
    // 修改发送缓冲区大小
    socklen_t socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -11;
    }
    printf("old send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof(socksval))) {
        printf("set send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -12;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -13;
    }
    printf("new send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    // 修改接收缓冲区大小
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -14;
    }
    printf("old receive buffer is %d, len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, sizeof(socksval))) {
        printf("set receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -15;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -16;
    }
    printf("new receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
#ifdef   USETLS
    SSL *tls = SSL_new(ctx);
    SSL_set_fd(tls, fd);
    if(SSL_connect(tls) == -1) {
        printf("ssl connect error");
        SSL_shutdown(tls);
        SSL_free(tls);
        close(fd);
        return -17;
    }
#endif
    unsigned char data[21+sizeof(password)-1];
    memset(data, 0, sizeof(data));
    memcpy(data + 21, password, sizeof(password)-1);
#ifdef   USETLS
    ssize_t len = SSL_write(tls, data, sizeof(data));
#else
    ssize_t len = write(fd, data, sizeof(data));
#endif
    if (len != sizeof(data)) {
        printf("write fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
#ifdef   USETLS
        SSL_shutdown(tls);
        SSL_free(tls);
#endif
        close(fd);
        return -18;
    }
#ifdef   USETLS
    len = SSL_read(tls, data, sizeof(data));
#else
    len = read(fd, data, sizeof(data));
#endif
    if (len != 1) {
        printf("read fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
#ifdef   USETLS
        SSL_shutdown(tls);
        SSL_free(tls);
#endif
        close(fd);
        return -19;
    }
    if (data[0] != 0x01) {
        printf("password check fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
#ifdef   USETLS
        SSL_shutdown(tls);
        SSL_free(tls);
#endif
        close(fd);
        return -20;
    }
    if (setnonblocking(fd) < 0) { // 设置为非阻塞IO
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
#ifdef   USETLS
        SSL_shutdown(tls);
        SSL_free(tls);
#endif
        close(fd);
        return -21;
    }
    socketclient->fd = fd;
#ifdef   USETLS
    socketclient->tls = tls;
#endif
    socketclient->packagelisthead = NULL;
    socketclient->remainsize = 0;
    socketclient->canwrite = 1;
    if (addtoepoll(socketclient)) {
        printf("tapfd addtoepoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
#ifdef   USETLS
        SSL_shutdown(tls);
        SSL_free(tls);
#endif
        close(fd);
        return -22;
    }
    return 0;
}

int removeclient (struct CLIENTLIST *client) {
    struct epoll_event ev;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, client->fd, &ev);
#ifdef   USETLS
    if (client->tls) {
        SSL_shutdown(client->tls);
        SSL_free(client->tls);
    }
#endif
    close(client->fd);
    struct PACKAGELIST *package = client->packagelisthead;
    while (package) {
        struct PACKAGELIST *tmppackage = package;
        package = package->tail;
        tmppackage->tail = remainpackagelisthead;
        remainpackagelisthead = tmppackage;
    }
    if (client == socketclient) { // 常规情况
        do {
            sleep(retryinterval);
            printf("try connect tcp socket again, in %s, at %d\n", __FILE__, __LINE__);
        }
        while (connect_socketfd(serverip, serverport));
    } else { // 基本不可能情况
        printf("errno: %d, exit 0, in %s, at %d\n", errno, __FILE__, __LINE__);
        perror("tap driver lose");
        exit(0);
    }
    return 0;
}

int writenode (struct CLIENTLIST *client) {
    struct PACKAGELIST *package = client->packagelisthead;
    client->packagelisthead = NULL;
    while (package) {
#ifdef   USETLS
        ssize_t len = SSL_write(client->tls, package->data, package->size);
#else
        ssize_t len = write(client->fd, package->data, package->size);
#endif
        if (len < 0) {
            client->packagelisthead = package;
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                if (client == tapclient) {
                    perror("tap write error");
                } else {
                    perror("socket write error");
                }
                removeclient(client);
                return -1;
            }
            if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                if (modepoll(client, EPOLLOUT)) { // 监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    removeclient(client);
                    return -2;
                }
                client->canwrite = 0;
            }
            break;
        }
        if (len < package->size) { // 缓冲区不足，已无法继续写入数据。
            unsigned int size = package->size - len;
            memcpy(package->data, package->data + len, size);
            package->size = size;
            client->packagelisthead = package;
            if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                if (modepoll(client, EPOLLOUT)) { // 监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    removeclient(client);
                    return -3;
                }
                client->canwrite = 0;
            }
            break;
        }
        if (client->canwrite == 0) { // 缓冲区尚有空间，并且之前已经提示不足
            if (modepoll(client, 0)) { // 取消监听可写事件
                printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                client->packagelisthead = package;
                removeclient(client);
                return -4;
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

int readdata (struct CLIENTLIST *sourceclient) {
    unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    static unsigned char *readbuff = NULL; // 这里是用于存储全部的需要写入的数据buf，
    static int32_t maxtotalsize = 0;
    struct CLIENTLIST *targetclient;
    ssize_t len;
    if (sourceclient == tapclient) { // tap驱动，原始数据，需要自己额外添加数据包长度。
        len = read(sourceclient->fd, readbuf + 2, MAXDATASIZE); // 这里最大只可能是1518
        if (len < 0) {
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                perror("tap read error");
                removeclient(sourceclient);
            }
            return -1;
        }
        readbuf[0] = len >> 8;
        readbuf[1] = len & 0xff;
        len += 2;
        targetclient = socketclient;
    } else { // 网络套接字。
#ifdef   USETLS
        len = SSL_read(sourceclient->tls, readbuf, MAXDATASIZE);
#else
        len = read(sourceclient->fd, readbuf, MAXDATASIZE);
#endif
        if (len < 0) {
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                perror("socket read error");
                removeclient(sourceclient);
            }
            return -2;
        }
        targetclient = tapclient;
    }
    unsigned int offset = 0;
    unsigned int totalsize;
    unsigned char *buff;
    if (sourceclient->remainsize > 0) {
        totalsize = sourceclient->remainsize + len;
        if (totalsize > maxtotalsize) {
            if (readbuff) {
                free (readbuff);
            }
            readbuff = (unsigned char*) malloc(totalsize * sizeof(unsigned char));
            if (readbuff == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -3;
            }
            maxtotalsize = totalsize;
        }
        memcpy(readbuff, sourceclient->remainpackage, sourceclient->remainsize);
        memcpy(readbuff + sourceclient->remainsize, readbuf, len);
        sourceclient->remainsize = 0;
        buff = readbuff;
    } else {
        totalsize = len;
        buff = readbuf;
    }
    struct CLIENTLIST *writeclient = NULL;
    while (offset < totalsize) {
        if (offset + 64 > totalsize) { // mac帧单个最小必须是64个，小于这个的数据包一定不完整
            int remainsize = totalsize - offset;
            memcpy(sourceclient->remainpackage, buff + offset, remainsize);
            sourceclient->remainsize = remainsize;
            break;
        }
        unsigned int packagesize = 256*buff[offset] + buff[offset+1] + 2; // 当前数据帧大小
        if (offset + packagesize > totalsize) {
            int remainsize = totalsize - offset;
            memcpy(sourceclient->remainpackage, buff + offset, remainsize);
            sourceclient->remainsize = remainsize;
            break;
        }
        struct PACKAGELIST *package;
        if (remainpackagelisthead) { // 全局数据包回收站不为空
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
        if (targetclient == tapclient) {
            memcpy(package->data, buff + offset + 2, packagesize);
            package->size = packagesize - 2;
        } else {
            memcpy(package->data, buff + offset, packagesize);
            package->size = packagesize;
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

int parseargs (int argc, char *argv[]) {
    strcpy(serverip, "192.168.56.101");
    serverport = 3480;
    strcpy(password, "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs");
    retryinterval = 5;
    for (int i = 1 ; i < argc ; i++) {
        if (!strcmp(argv[i], "-h")) {
            i++;
            if (strlen(argv[i]) >= 255) {
                printf("server ip too long, in %s, at %d\n",  __FILE__, __LINE__);
                return -1;
            }
            strcpy(serverip, argv[i]);
        } else if (!strcmp(argv[i], "-p")) {
            i++;
            serverport = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-k")) {
            i++;
            if (strlen(argv[i]) != 32) {
                printf("access key must 32 bytes, in %s, at %d\n",  __FILE__, __LINE__);
                return -2;
            }
            strcpy(password, argv[i]);
        } else if (!strcmp(argv[i], "-r")) {
            i++;
            retryinterval = atoi(argv[i]);
        } else {
            printf("build time: %s %s\n", __DATE__, __TIME__);
            printf("-h server host, default is 192.168.56.101\n");
            printf("-p server port, default is 3480\n");
            printf("-k access key, default is vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs\n");
            printf("-r retry interval, unit is second, default is 5\n");
            return -3;
        }
    }
    return 0;
}

int main (int argc, char *argv[]) {
#ifdef   USETLS
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
#endif
    if (parseargs (argc, argv)) {
        return -1;
    }
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
                readdata(client);
            } else if (events & EPOLLOUT) {
                writenode(client);
            } else {
                printf("receive new event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
            }
        }
    }
#ifdef   USETLS
    SSL_CTX_free(ctx);
#endif
    return 0;
}
