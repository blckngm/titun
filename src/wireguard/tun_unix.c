#include <sys/ioctl.h>
#include <net/if.h>
#ifdef linux
#include <string.h>
#include <linux/if_tun.h>
#elif __FreeBSD__
#include <net/if_tun.h>
#endif

#ifdef linux
int tunsetiff(int tun_fd, const char* name) {
    struct ifreq req;
    strncpy(req.ifr_name, name, IF_NAMESIZE);
    req.ifr_flags = IFF_TUN | IFF_NO_PI;
    return ioctl(tun_fd, TUNSETIFF, &req);
}
#endif

#ifdef __FreeBSD__
int tunsifhead(int tun_fd) {
    int v = 1;
    return ioctl(tun_fd, TUNSIFHEAD, &v);
}
#endif

int get_mtu(int socket_fd, unsigned int ifindex) {
    struct ifreq req;
    int r;

    #if defined SIOCGIFNAME || defined linux
    req.ifr_ifindex = ifindex;
    r = ioctl(socket_fd, SIOCGIFNAME, &req);
    if (r < 0) {
        return -1;
    }
    #else
    if (if_indextoname(ifindex, req.ifr_name) == NULL) {
        return -1;
    }
    #endif

    r = ioctl(socket_fd, SIOCGIFMTU, &req);
    if (r < 0) {
        return r;
    }
    return req.ifr_mtu;
}
