#if __APPLE__
#include <TargetConditionals.h>
#endif

#include <sys/ioctl.h>
#include <net/if.h>
#ifdef linux
#include <string.h>
#include <linux/if_tun.h>
#elif __FreeBSD__
#include <net/if_tun.h>
#elif TARGET_OS_MAC
#include <unistd.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <fcntl.h>
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

#ifdef TARGET_OS_MAC

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2

int open_utun_socket(uint32_t sc_unit)
{
    struct sockaddr_ctl addr;
    struct ctl_info info;
    int fd;
    int err;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
        return fd;

    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

    err = ioctl(fd, CTLIOCGINFO, &info);
    if (err != 0)
        goto on_error;

    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = sc_unit;

    err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (err != 0)
        goto on_error;

    err = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (err != 0)
        goto on_error;

    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (err != 0)
        goto on_error;

on_error:
    if (err != 0)
    {
        close(fd);
        return err;
    }

    return fd;
}
#endif
