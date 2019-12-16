# 沃航科技自己开发，自己使用的vpn软件

本工具不是什么翻墙的工具，只是用于将类似拥有公网ip，但是性能却很差的云服务器与本地高配的服务器之间建立一条虚拟的网络，让其他用户访问公网的时候，相当于访问局域网一样。

## 为什么要开发它呢?

因为随着公司业务的发展，公司对服务器配置的要求也越来越高了，可是由于高配的云服务器价格居高不下，如果自己牵独立ip的宽带，或是服务器托管，成本也不小。考虑到成本问题，小沃决定买一台低配的云服务器，然后通过linux的tap/tun技术通过tcp通道，在云服务器与本地服务器之间建立一条虚拟的通道，然后利用iptables将特定的端口映射到本地的服务器去。总而言之一句话，就是为了省钱。

## 它能做什么

考虑到产品的定位，这个产品只会开发linux版本，而且不会有过多的配置，本软件考虑的最多的还是性能，因为我买的那台服务器是一台配置最低的阿里云服务器，所以考虑醉倒的肯定是性能问题。本软件使用的是epoll技术，理论上是可以实现高并发的，具体可实现的功能如下：
1. 可以搭建一个虚拟局域网，让在不同地域的主机看起来就像是在同一个局域网内一样。
2. 可以自定义端口，防止与你正在使用的端口相冲突。
3. 不适合翻墙，不适合翻墙，只是用于建立虚拟局域网用的。

## 编译命令

```
gcc -O3 -o server server.c -lpthread
gcc -O3 -o client client.c -lpthread
```

## 未来展望

无，既然是自己使用的，肯定不会听从各网友朋友的建议，产品未来的规划更多的是根据公司的实际发展与实际需求决定。

## 版权问题

注意，本软件原理简单，但是如果有网友利用本软件开发其他的产品，需要遵守gnu v3协议，将其他相关产品的代码全部开源。
