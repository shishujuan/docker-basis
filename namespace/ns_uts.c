/*
ns_uts.c: used to test uts namespace. copy from: https://blog.yadutaf.fr/2013/12/22/introduction-to-linux-namespaces-part-1-uts/
(needs root privileges (or appropriate capabilities))
*/

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];
char* const child_args[] = {
  "/bin/bash",
  NULL
};

int child_main(void* arg)
{
  printf(" - World !\n");
  sethostname("In Namespace", 12);
  execv(child_args[0], child_args);
  printf("Ooops\n");
  return 1;
}

int main()
{
  printf(" - Hello ?\n");
  int child_pid = clone(child_main, child_stack+STACK_SIZE,
      CLONE_NEWUTS | SIGCHLD, NULL);
  waitpid(child_pid, NULL, 0);
  return 0;
}
