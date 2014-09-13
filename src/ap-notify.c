#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <linux/nl80211.h>

#define print_err(...) fprintf(stderr, __VA_ARGS__)

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

static struct nl_sock *sk = NULL;

static int get_addr(struct nlattr *tb[], uint8_t **addr)
{
	if (tb[NL80211_ATTR_MAC] == NULL)
		return -1;
	*addr = nla_data(tb[NL80211_ATTR_MAC]);
	return 0;
}

static int nlCallback(struct nl_msg* msg, void* arg)
{
	struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(ret_hdr);
	struct nlattr *tb[NL80211_ATTR_MAX + 1];

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	uint8_t *addr;

	switch(gnlh->cmd) {
	case NL80211_CMD_NEW_STATION:
		if (get_addr(tb, &addr) < 0)
			printf("New station: no MAC\n");
		else
			printf("New station: "MACSTR"\n", MAC2STR(addr));
		break;
	case NL80211_CMD_DEL_STATION:
		if (get_addr(tb, &addr) < 0)
			printf("Del station: no MAC\n");
		else
			printf("Del station: "MACSTR"\n", MAC2STR(addr));
		break;
	default:
		return NL_SKIP;
	}



	return 0;
}

static int cleanup_and_exit(int ret)
{
	if (sk != NULL)
		nl_socket_free(sk);
	exit(ret);
}

static void signal_handler(int sig)
{
	cleanup_and_exit(EXIT_SUCCESS);
}

int main()
{
	int ret;
	int sk_fd;
	fd_set rfds;

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	sk = nl_socket_alloc();
	if (sk == NULL) {
		print_err("Unable to allocate Netlink socket\n");
		exit(EXIT_FAILURE);
	}

	ret = genl_connect(sk);
	if (ret < 0) {
		print_err("no connect %d\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	printf("Netlink socket connected\n");

	ret = genl_ctrl_resolve_grp(sk, "nl80211", "mlme");
	if (ret < 0) {
		print_err("MLME group not found %d\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	ret = nl_socket_add_membership(sk, ret);
	if (ret < 0) {
		print_err("Unable to join multicast group %d\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	nl_socket_disable_seq_check(sk);
	ret = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
				  nlCallback, NULL);
	if (ret < 0) {
		print_err("Unable to register callback %d\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	while (1) {
		FD_ZERO(&rfds);

		sk_fd = nl_socket_get_fd(sk);
		FD_SET(sk_fd, &rfds);

		ret = select(sk_fd + 1, &rfds, NULL, NULL, NULL);
		if (ret < 0)
			break;

		ret = nl_recvmsgs_default(sk);
		if (ret < 0) {
			print_err("Error receiving message %d\n", ret);
			cleanup_and_exit(EXIT_FAILURE);
		}
	}

	cleanup_and_exit(EXIT_FAILURE);
}
