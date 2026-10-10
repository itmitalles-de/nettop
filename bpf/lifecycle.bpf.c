// SPDX-License-Identifier: GPL-3.0-or-later
// Metadata-only socket observations. Packet capture remains the byte source.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// Only fields consumed by CO-RE are declared; target BTF supplies real offsets.
struct in6_addr { union { __u8 u6_addr8[16]; __u32 u6_addr32[4]; } in6_u; };
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
struct possible_net_t { struct net *net; } __attribute__((preserve_access_index));
struct inode { unsigned long i_ino; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; } __attribute__((preserve_access_index));
struct sock_common {
    __u32 skc_daddr, skc_rcv_saddr;
    __u16 skc_dport, skc_num, skc_family;
    struct possible_net_t skc_net;
    struct in6_addr skc_v6_daddr, skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));
struct socket;
struct sock {
    struct sock_common __sk_common;
    struct socket *sk_socket;
    __u16 sk_protocol;
} __attribute__((preserve_access_index));
struct socket { struct file *file; struct sock *sk; } __attribute__((preserve_access_index));
struct msghdr { void *msg_name; int msg_namelen; } __attribute__((preserve_access_index));
struct task_struct {
    unsigned int flags;
    struct task_struct *group_leader;
    __u64 start_boottime;
    char comm[16];
} __attribute__((preserve_access_index));

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SEND 1
#define RECV 2
#define CONNECT 3
#define CLOSE 4
#define ACCEPT 5
#define BIND 6
#define BIRTH 7
#define CONNECT6_KEY 8
#define UNRELIABLE_ACTOR 1
#define UNKNOWN_PEER 2
#define PF_IO_WORKER 0x00000010
#define PF_KTHREAD 0x00200000

// Shared ABI: all ports host-endian, IP address bytes network-endian.
struct lifecycle_event {
    __u64 timestamp_ns, started_ns, process_start_ns, socket_id, inode;
    __u32 tgid, uid, netns;
    __u16 family, protocol, local_port, remote_port;
    __u8 kind, flags;
    __u16 reserved;
    __u8 local_addr[16], remote_addr[16];
    char comm[16];
};
_Static_assert(sizeof(struct lifecycle_event) == 112, "lifecycle event ABI");
struct statistics { __u64 lost_events, pending_failures, socket_failures, read_failures; };
struct pending_key { __u64 tid; __u32 kind; __u32 pad; };
struct call_state { __u64 started_ns; __u8 peer[28]; __u32 peer_len, depth, nested; };
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct pending_key);
    __type(value, struct call_state);
} pending SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} socket_ids SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sequence SEC(".maps");

static __always_inline void failure(int which)
{
    __u32 zero = 0;
    struct statistics *s = bpf_map_lookup_elem(&stats, &zero);
    if (!s) return;
    if (which == 0) __sync_fetch_and_add(&s->lost_events, 1);
    else if (which == 1) __sync_fetch_and_add(&s->pending_failures, 1);
    else if (which == 2) __sync_fetch_and_add(&s->socket_failures, 1);
    else __sync_fetch_and_add(&s->read_failures, 1);
}

static __always_inline int supported(struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol);
    return (family == AF_INET || family == AF_INET6) &&
           (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
}

static __always_inline __u64 incarnation(struct sock *sk)
{
    __u64 key = (__u64)sk;
    __u64 *value = bpf_map_lookup_elem(&socket_ids, &key);
    if (value) return *value;
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&sequence, &zero);
    if (!counter) return 0;
    __u64 id = __sync_fetch_and_add(counter, 1) + 1;
    if (bpf_map_update_elem(&socket_ids, &key, &id, BPF_NOEXIST)) {
        // Another CPU can observe this socket concurrently.
        value = bpf_map_lookup_elem(&socket_ids, &key);
        if (value) return *value;
        failure(2);
        return 0;
    }
    return id;
}

static __always_inline void save_peer(struct call_state *state, struct msghdr *msg)
{
    int len = BPF_CORE_READ(msg, msg_namelen);
    void *name = BPF_CORE_READ(msg, msg_name);
    if (name && len >= 16) {
        // sockaddr_in(16) or sockaddr_in6(28); never read user payload.
        if (len >= 28) {
            if (!bpf_probe_read_kernel(state->peer, 28, name)) state->peer_len = 28;
            else failure(3);
        } else {
            if (!bpf_probe_read_kernel(state->peer, 16, name)) state->peer_len = 16;
            else failure(3);
        }
    }
}

static __always_inline int enter_call(struct sock *sk, struct msghdr *msg, __u32 kind)
{
    if (!sk || !supported(sk)) return 0;
    struct pending_key key = { .tid = bpf_get_current_pid_tgid(), .kind = kind };
    struct call_state *active = bpf_map_lookup_elem(&pending, &key);
    if (active) {
        active->depth++;
        active->nested = 1;
        failure(1);
        return 0;
    }
    struct call_state state = { .started_ns = bpf_ktime_get_ns(), .depth = 1 };
    if (kind == SEND && msg) save_peer(&state, msg);
    // Never overwrite an in-flight nested call with falsely matching metadata.
    if (bpf_map_update_elem(&pending, &key, &state, BPF_NOEXIST)) failure(1);
    return 0;
}

static __always_inline void emit(struct sock *sk, struct socket *sock,
                                struct call_state *state, __u8 kind)
{
    __u64 id = incarnation(sk);
    if (!id) return;
    struct lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { failure(0); return; }
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->started_ns = state->started_ns;
    e->socket_id = id;
    e->kind = kind;
    e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->protocol = BPF_CORE_READ(sk, sk_protocol);
    e->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    e->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (sock) e->inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
    if (e->family == AF_INET) {
        __u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->local_addr, &local, 4);
        __builtin_memcpy(e->remote_addr, &remote, 4);
    } else {
        BPF_CORE_READ_INTO(&e->local_addr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->remote_addr, sk, __sk_common.skc_v6_daddr);
    }
    // Datagram calls may use a peer without connecting the socket.
    if (e->protocol == IPPROTO_UDP && state->peer_len >= 16) {
        __u16 peer_family;
        __builtin_memcpy(&peer_family, state->peer, 2);
        if (peer_family == AF_INET && e->family == AF_INET) {
            __u16 port;
            __builtin_memcpy(&port, state->peer + 2, 2);
            e->remote_port = bpf_ntohs(port);
            __builtin_memcpy(e->remote_addr, state->peer + 4, 4);
        } else if (peer_family == AF_INET6 && e->family == AF_INET6 && state->peer_len >= 28) {
            __u16 port;
            __builtin_memcpy(&port, state->peer + 2, 2);
            e->remote_port = bpf_ntohs(port);
            __builtin_memcpy(e->remote_addr, state->peer + 8, 16);
        }
    }
    if (!e->remote_port) e->flags |= UNKNOWN_PEER;
    // A newly cloned TCP child is created in packet/softirq context. Its
    // current task is not its eventual owner; only later ACCEPT supplies that.
    if (kind != BIRTH) {
        __u64 tid = bpf_get_current_pid_tgid();
        e->tgid = tid >> 32;
        e->uid = (__u32)bpf_get_current_uid_gid();
        struct task_struct *task = (void *)bpf_get_current_task();
        struct task_struct *leader = BPF_CORE_READ(task, group_leader);
        e->process_start_ns = BPF_CORE_READ(leader, start_boottime);
        BPF_CORE_READ_STR_INTO(&e->comm, leader, comm);
        if (BPF_CORE_READ(task, flags) & (PF_IO_WORKER | PF_KTHREAD)) e->flags |= UNRELIABLE_ACTOR;
    }
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int leave_call(struct sock *sk, struct socket *sock,
                                     struct msghdr *msg, __u32 kind, int result)
{
    struct pending_key key = { .tid = bpf_get_current_pid_tgid(), .kind = kind };
    struct call_state *saved = bpf_map_lookup_elem(&pending, &key);
    if (!saved) return 0;
    if (saved->depth > 1) { saved->depth--; return 0; }
    struct call_state state = *saved;
    bpf_map_delete_elem(&pending, &key);
    if (state.nested || result < 0 || !sk || !supported(sk)) return 0;
    if (kind == RECV && msg) save_peer(&state, msg);
    emit(sk, sock, &state, kind == CONNECT6_KEY ? CONNECT : kind);
    return 0;
}

// Userspace sendto/sendmsg bypass the exported sock_sendmsg wrapper on
// modern kernels. Both IP-family dispatchers cover those paths and write(2).
SEC("fentry/inet_sendmsg")
int BPF_PROG(send4_enter, struct socket *sock, struct msghdr *msg, unsigned long size)
{ return enter_call(BPF_CORE_READ(sock, sk), msg, SEND); }
SEC("fexit/inet_sendmsg")
int BPF_PROG(send4_exit, struct socket *sock, struct msghdr *msg, unsigned long size, int result)
{ return leave_call(BPF_CORE_READ(sock, sk), sock, msg, SEND, result); }
SEC("fentry/inet6_sendmsg")
int BPF_PROG(send6_enter, struct socket *sock, struct msghdr *msg, unsigned long size)
{ return enter_call(BPF_CORE_READ(sock, sk), msg, SEND); }
SEC("fexit/inet6_sendmsg")
int BPF_PROG(send6_exit, struct socket *sock, struct msghdr *msg, unsigned long size, int result)
{ return leave_call(BPF_CORE_READ(sock, sk), sock, msg, SEND, result); }
// recvmmsg can bypass sock_recvmsg after the first datagram; use the
// family dispatchers so batched calls still produce one event per operation.
SEC("fentry/inet_recvmsg")
int BPF_PROG(recv4_enter, struct socket *sock, struct msghdr *msg, unsigned long size, int flags)
{ return enter_call(BPF_CORE_READ(sock, sk), msg, RECV); }
SEC("fexit/inet_recvmsg")
int BPF_PROG(recv4_exit, struct socket *sock, struct msghdr *msg, unsigned long size, int flags, int result)
{ return leave_call(BPF_CORE_READ(sock, sk), sock, msg, RECV, result); }
SEC("fentry/inet6_recvmsg")
int BPF_PROG(recv6_enter, struct socket *sock, struct msghdr *msg, unsigned long size, int flags)
{ return enter_call(BPF_CORE_READ(sock, sk), msg, RECV); }
SEC("fexit/inet6_recvmsg")
int BPF_PROG(recv6_exit, struct socket *sock, struct msghdr *msg, unsigned long size, int flags, int result)
{ return leave_call(BPF_CORE_READ(sock, sk), sock, msg, RECV, result); }
SEC("fentry/tcp_v4_connect")
int BPF_PROG(connect4_enter, struct sock *sk, void *address, int addrlen)
{ return enter_call(sk, 0, CONNECT); }
SEC("fexit/tcp_v4_connect")
int BPF_PROG(connect4_exit, struct sock *sk, void *address, int addrlen, int result)
{ return leave_call(sk, BPF_CORE_READ(sk, sk_socket), 0, CONNECT, result); }
SEC("fentry/tcp_v6_connect")
int BPF_PROG(connect6_enter, struct sock *sk, void *address, int addrlen)
{ return enter_call(sk, 0, CONNECT6_KEY); }
SEC("fexit/tcp_v6_connect")
int BPF_PROG(connect6_exit, struct sock *sk, void *address, int addrlen, int result)
{ return leave_call(sk, BPF_CORE_READ(sk, sk_socket), 0, CONNECT6_KEY, result); }
static __always_inline int bound_socket(void *ctx)
{
    __u64 argument = 0, result = 0;
    if (bpf_get_func_arg(ctx, 0, &argument) || bpf_get_func_ret(ctx, &result)) {
        failure(3);
        return 0;
    }
    if ((__s64)result < 0 || !argument) return 0;
    struct socket *sock = (void *)argument;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk || !supported(sk)) return 0;
    struct call_state state = { .started_ns = bpf_ktime_get_ns() };
    emit(sk, sock, &state, BIND);
    return 0;
}
SEC("fexit/inet_bind")
int bind4_exit(void *ctx)
{ return bound_socket(ctx); }
SEC("fexit/inet6_bind")
int bind6_exit(void *ctx)
{ return bound_socket(ctx); }

// inet_accept gained a different trailing argument on newer kernels. The
// first two arguments and signed result are stable; tracing helpers avoid
// hardcoding the return-value context offset from one kernel prototype.
SEC("fexit/inet_accept")
int socket_accept(void *ctx)
{
    __u64 argument = 0, result = 0;
    if (bpf_get_func_arg(ctx, 1, &argument) || bpf_get_func_ret(ctx, &result)) {
        failure(3);
        return 0;
    }
    if ((__s64)result < 0 || !argument) return 0;
    struct socket *sock = (void *)argument;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk || !supported(sk)) return 0;
    struct call_state state = { .started_ns = bpf_ktime_get_ns() };
    emit(sk, sock, &state, ACCEPT);
    return 0;
}
SEC("fexit/inet_csk_clone_lock")
int socket_birth(void *ctx)
{
    __u64 result = 0;
    if (bpf_get_func_ret(ctx, &result)) { failure(3); return 0; }
    struct sock *sk = (void *)result;
    if (!sk || !supported(sk)) return 0;
    struct call_state state = { .started_ns = bpf_ktime_get_ns() };
    emit(sk, 0, &state, BIRTH);
    return 0;
}

// Unaccepted TCP children never receive inet_release. Remove their opaque ID
// at actual final destruction, without creating another ID or naming a task.
SEC("fentry/__sk_free")
int BPF_PROG(socket_freed, struct sock *sk)
{
    __u64 key = (__u64)sk;
    bpf_map_delete_elem(&socket_ids, &key);
    return 0;
}

SEC("fentry/inet_release")
int BPF_PROG(socket_close, struct socket *sock)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk || !supported(sk)) return 0;
    struct call_state state = { .started_ns = bpf_ktime_get_ns() };
    emit(sk, sock, &state, CLOSE);
    __u64 key = (__u64)sk;
    bpf_map_delete_elem(&socket_ids, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
