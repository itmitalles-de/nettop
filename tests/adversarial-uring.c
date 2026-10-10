/* Force an io_uring UDP send through an io-wq worker, with a passive FD holder. */
#include <arpa/inet.h>
#include <assert.h>
#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    assert(argc == 2);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in dst = {.sin_family=AF_INET, .sin_port=htons(atoi(argv[1])), .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(connect(fd, (struct sockaddr *)&dst, sizeof(dst)) == 0);
    int hold[2]; assert(pipe(hold) == 0);
    pid_t parent = getpid(), passive = fork(); assert(passive >= 0);
    if (passive == 0) {
        /* Do not leave a child behind if the test's monitor/assertion fails. */
        assert(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);
        if (getppid() != parent) _exit(0);
        close(hold[1]); char done; ssize_t read_result = read(hold[0], &done, 1); _exit(read_result < 0 ? 1 : 0);
    }
    close(hold[0]);
    struct io_uring ring;
    int result = io_uring_queue_init(8, &ring, 0);
    if (result < 0) { fprintf(stderr, "io_uring_queue_init: %d\n", result); return 1; }
    char payload[1024] = {0};
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring); assert(sqe);
    io_uring_prep_send(sqe, fd, payload, sizeof(payload), 0);
    sqe->flags |= IOSQE_ASYNC;
    assert(io_uring_submit(&ring) == 1);
    struct io_uring_cqe *cqe;
    assert(io_uring_wait_cqe(&ring, &cqe) == 0);
    assert(cqe->res == (int)sizeof(payload));
    io_uring_cqe_seen(&ring, cqe);
    printf("{\"actor\":%d,\"passive_holder\":%d,\"forced_async\":true,\"bytes\":1024}\n", getpid(), passive);
    fflush(stdout);
    (void)getchar();
    io_uring_queue_exit(&ring); close(fd); close(hold[1]);
    assert(waitpid(passive, NULL, 0) == passive);
    return 0;
}
