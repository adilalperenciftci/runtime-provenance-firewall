// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define EVENT_EXEC 1
#define EVENT_FILE_OPEN_WRITE 2
#define EVENT_FILE_OPEN_SENSITIVE 3
#define EVENT_NETWORK_CONNECT4 4
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define WRITE_OPEN_FLAGS (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)

struct security_event {
    __u64 monotonic_ns;
    __u64 cgroup_id;
    __u64 start_time_ns;
    __u64 parent_start_time_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 pid_namespace;
    __u32 mount_namespace;
    __u32 parent_pid_namespace;
    __u32 kind;
    __u32 flags;
    __u32 destination_ipv4;
    __u32 destination_port;
    __u32 protocol;
    char comm[TASK_COMM_LEN];
    char filename[PATH_LEN];
};

struct pending_open {
    __u32 flags;
    __u32 kind;
    char filename[PATH_LEN];
};

struct trace_event_raw_sched_process_exec___local {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    pid_t pid;
    pid_t old_pid;
    char __data[0];
};

struct trace_event_raw_sys_enter___local {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit___local {
    struct trace_entry ent;
    long id;
    long ret;
};

const volatile __u64 target_cgroup_id = 0;
const volatile char target_sensitive_path[PATH_LEN] = {};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} correlation_drops SEC(".maps");

#define LOSS_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __uint(max_entries, 1); \
    __type(key, __u32); \
    __type(value, __u64); \
} name SEC(".maps")

LOSS_MAP(path_read_drops);
LOSS_MAP(map_update_drops);
LOSS_MAP(cgroup_mismatch_drops);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_open);
} pending_opens SEC(".maps");

static __always_inline __u32 active_pid_namespace(struct task_struct *task)
{
    struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
    if (!thread_pid)
        return 0;

    __u32 level = BPF_CORE_READ(thread_pid, level);
    if (level > 32)
        return 0;

    struct pid_namespace *namespace;
    bpf_core_read(&namespace, sizeof(namespace), &thread_pid->numbers[level].ns);
    if (!namespace)
        return 0;
    return BPF_CORE_READ(namespace, ns.inum);
}

static __always_inline __u32 mount_namespace(struct task_struct *task)
{
    struct nsproxy *proxy = BPF_CORE_READ(task, nsproxy);
    if (!proxy)
        return 0;
    struct mnt_namespace *namespace = BPF_CORE_READ(proxy, mnt_ns);
    if (!namespace)
        return 0;
    return BPF_CORE_READ(namespace, ns.inum);
}

static __always_inline void increment_counter(void *map)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(map, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline struct security_event *reserve_event(void)
{
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(&ringbuf_drops);
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    return event;
}

static __always_inline void fill_process(struct security_event *event)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    event->monotonic_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->start_time_ns = BPF_CORE_READ(task, start_boottime);
    event->parent_start_time_ns = BPF_CORE_READ(parent, start_boottime);
    event->pid = (__u32)pid_tgid;
    event->tgid = pid_tgid >> 32;
    event->ppid = BPF_CORE_READ(parent, tgid);
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->pid_namespace = active_pid_namespace(task);
    event->mount_namespace = mount_namespace(task);
    event->parent_pid_namespace = active_pid_namespace(parent);
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline bool path_matches_sensitive(const char path[PATH_LEN])
{
    if (target_sensitive_path[0] == '\0')
        return false;
    for (int index = 0; index < PATH_LEN; index++) {
        if (path[index] != target_sensitive_path[index])
            return false;
        if (path[index] == '\0')
            return true;
    }
    return false;
}

SEC("tracepoint/sched/sched_process_exec")
int observe_exec(struct trace_event_raw_sched_process_exec___local *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (target_cgroup_id == 0 || cgroup_id != target_cgroup_id)
        return 0;

    struct security_event *event = reserve_event();
    if (!event)
        return 0;

    fill_process(event);
    event->kind = EVENT_EXEC;

    __u32 filename_offset = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_str(event->filename, sizeof(event->filename), (void *)ctx + filename_offset);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int observe_openat_enter(struct trace_event_raw_sys_enter___local *ctx)
{
    if (bpf_get_current_cgroup_id() != target_cgroup_id)
        return 0;

    __u64 key = bpf_get_current_pid_tgid();
    struct pending_open pending = {};
    pending.flags = (__u32)ctx->args[2];
    if ((pending.flags & WRITE_OPEN_FLAGS) == 0 && target_sensitive_path[0] == '\0')
        return 0;
    long path_length = bpf_probe_read_user_str(pending.filename, sizeof(pending.filename), (void *)ctx->args[1]);
    if (path_length < 0 || path_length >= sizeof(pending.filename)) {
        increment_counter(&path_read_drops);
        increment_counter(&correlation_drops);
        return 0;
    }
    if (path_matches_sensitive(pending.filename))
        pending.kind = EVENT_FILE_OPEN_SENSITIVE;
    else if ((pending.flags & WRITE_OPEN_FLAGS) != 0)
        pending.kind = EVENT_FILE_OPEN_WRITE;
    else
        return 0;
    if (bpf_map_update_elem(&pending_opens, &key, &pending, BPF_ANY) < 0) {
        increment_counter(&map_update_drops);
        increment_counter(&correlation_drops);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int observe_openat_exit(struct trace_event_raw_sys_exit___local *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_open *pending = bpf_map_lookup_elem(&pending_opens, &key);
    if (!pending)
        return 0;

    if (bpf_get_current_cgroup_id() != target_cgroup_id) {
        increment_counter(&cgroup_mismatch_drops);
        increment_counter(&correlation_drops);
        bpf_map_delete_elem(&pending_opens, &key);
        return 0;
    }

    if (ctx->ret >= 0) {
        struct security_event *event = reserve_event();
        if (event) {
            fill_process(event);
            event->kind = pending->kind;
            event->flags = pending->flags;
            __builtin_memcpy(event->filename, pending->filename, sizeof(event->filename));
            bpf_ringbuf_submit(event, 0);
        }
    }
    bpf_map_delete_elem(&pending_opens, &key);
    return 0;
}

SEC("cgroup/connect4")
int observe_connect4(struct bpf_sock_addr *ctx)
{
    if (bpf_get_current_cgroup_id() != target_cgroup_id)
        return 1;

    struct security_event *event = reserve_event();
    if (!event)
        return 1;

    fill_process(event);
    event->kind = EVENT_NETWORK_CONNECT4;
    event->destination_ipv4 = ctx->user_ip4;
    event->destination_port = bpf_ntohs(ctx->user_port);
    event->protocol = ctx->protocol;
    bpf_ringbuf_submit(event, 0);
    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
