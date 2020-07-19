from __future__ import print_function
from bcc import BPF
from time import sleep

# arguments
def rang_chect(string)
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

help = """help:
    ./flow          # trace send/recv flow by host 
    ./flow -p 100   # only trace PID 100
"""

parser = argparse.ArgumentParser(
    description = "Summarize send and recv flow by host",
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog = example
)
parser.add_argument("-p", "--pid", 
    help = "Trace this pid only")

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 pid;
}

BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

int kprobe__tcp_send(struct pte_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_send_bytes.increment(ipv4_key, size);

    }
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u32 pid bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u16 family = sk->__sk_common.skc_family;
    u64 *val, zero =0;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key {.pid = pid};
        ipv4_recv_bytes.increment(ipv4_key, copied);
    }
}

"""

# code substitutions
if arg.pid:
    bpf_program = bpf_program.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_program = bpf_program.replace('FILTER_PID','')

SessionKey = namedtuple('Session',['pid'])

def pid_to_comm(pid)
    try:
        comm = open("/proc/%s/comm" % pid, "r").read().rstrip()
        return comm
    except IOError:
        return str(pid)

def get_ipv4_session_key(k):
    return SessionKey(pid=k.pid)

# init bpf
b = BPF(text=bpf_program)

ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]

# output
i = 0
exiting = False

while i != arg.count and not exiting:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True

ipv4_throughput = defaultdict(lambda:[0,0])
for k, v in ipv4_send_bytes.items():
    key = get_ipv4_session_key(k)
    ipv4_throughput[key][0] = v.value
ipv4_send_bytes.clear()

for k,v in ipv4_recv_bytes.items():
    key = get_ipv4_session_key(key)
    ipv4_throughput[key][1] = v.value
ipv4_recv_bytes.clear()

if ipv4_throughput:
    print(%-6s %6s %6s) % ("PID", "RX_KB", "TX_KB")

for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                          key=lambda kv: sum(kv[1]),
                                          reverse=True):
    print("%-6d %6d %6d" % (k.pid, int(recv_bytes / 1024), int(send_bytes / 1024)))

    i += 1
