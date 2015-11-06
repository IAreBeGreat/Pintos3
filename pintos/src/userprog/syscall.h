#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

struct child_process {
	int pid;
	int status;
	bool wait;
	bool exit;
	struct list_elem elem;
};

struct child_process* add_child(int pid);
struct child_process* get_child(int pid);
void remove_child(struct child_process * cp);

#endif /* userprog/syscall.h */
