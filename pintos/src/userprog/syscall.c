#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static int getArgument(struct intr_frame *, int);
static int valid_argument(struct intr_frame * f, int index);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{ 
  int syscall_num;
  struct fd_file_pair *f_pair;
  memcpy( &syscall_num, f->esp, sizeof(int));
  
  switch(syscall_num)
  { 
    case(SYS_HALT):
      shutdown_power_off();
      break;
    case(SYS_EXIT):
    {
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
      exit(getArgument(f,1));

      f->eax = 0;
      thread_exit();

      break;
    }
    case(SYS_EXEC):
    {
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
		  f->eax = exec((const char *)getArgument(f,1));
      break;
    }
    case(SYS_WAIT):
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
      f->eax = wait(getArgument(f,1));
      break;
    case(SYS_CREATE):
      if(!valid_argument(f,1) || !valid_argument(f,2))
      {
        f->eax=-1;
        thread_exit();
      }
      f->eax = filesys_create(getArgument(f,1),getArgument(f,2));
      break;
    case(SYS_REMOVE):
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
      f->eax = filesys_remove(getArgument(f,1));
      break;
    case(SYS_OPEN):
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
      f_pair = calloc(1, sizeof (struct fd_file_pair));
      f_pair->file = file_open(file_get_inode(getArgument(f,1)));
      if(f_pair->file == NULL)
      {
        printf("File opening failed");
        f->eax = -1;
        thread_exit();
        break;
      }
      f_pair->fd = thread_current()->fd_index;
      thread_current()->fd_index++;
      list_push_front(&thread_current()->fd_file_list, &f_pair->file_elem);
      f->eax=f_pair->fd;
      break;
    case(SYS_FILESIZE):
      printf("filesize call");
      thread_exit();
      break;
    case(SYS_READ):
      if(!valid_argument(f,1)||!valid_argument(f,2)||!valid_argument(f,3)) 
      {
        f->eax=-1;
        thread_exit();
      } 
      if(getArgument(f,1))
        input_getc();
      else if(getArgument(f,1)<thread_current()->fd_index)
      {
        f_pair = get_fd_file_pair(getArgument(f,1));
        f->eax=(file_read(f_pair->file, getArgument(f,2), getArgument(f,3)));
      }
      break;
    case(SYS_WRITE):
      if(!valid_argument(f,1)||!valid_argument(f,2)||!valid_argument(f,3))
      {
        f->eax=-1;
        thread_exit();
      }
      if(getArgument(f,1) == 1)
      {
		    putbuf(getArgument(f,2), getArgument(f,3));
		    f->eax = 0;
		  }
		  else if(getArgument(f,1)>1 && getArgument(f,1) < thread_current()->fd_index)
		     f->eax = file_write(get_fd_file_pair(getArgument(f,1))->file, getArgument(f,2), getArgument(f,3));
      break;
    case(SYS_SEEK):
      if(!valid_argument(f,1)||!valid_argument(f,2))
      {
        f->eax=-1;
        thread_exit();
      }
      int fd = getArgument(f, 1);
      if(fd < (thread_current()->fd_index))
      {
        f_pair = get_fd_file_pair(fd);
        file_seek(f_pair->file, getArgument(f,2));
      }
      break;
    case(SYS_TELL): 
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
      if(getArgument(f,1)<2 || getArgument(f,1) > thread_current()->fd_index)
      {
        printf("tell fail"); 
        thread_exit();
      }
      f->eax = file_tell(get_fd_file_pair(getArgument(f,1))->file);
      break;
    case(SYS_CLOSE):
      if(!valid_argument(f,1))
      {
        f->eax=-1;
        thread_exit();
      }
      if(getArgument(f,1)<2 || getArgument(f,1) > thread_current()->fd_index)
      {
        printf("close fail"); 
        thread_exit();
      }
      f_pair = get_fd_file_pair(getArgument(f,1));
      file_close(f_pair->file);
      break;
    default: 
      printf("default, something went wrong");
      thread_exit();
  }
}

void exit(int status)
{
	struct thread *cur = thread_current();
	if(thread_alive(cur->parent))
	{
		cur->cp->status = status;
	}
	printf("%s: exit(%d)\n",cur->name,status);
	thread_exit();
}

pid_t exec (const char *cmd_line)
{
	pid_t pid  = process_execute(cmd_line);
	return pid;
}


int wait(pid_t pid)
{
	return process_wait(pid);
}

static int getArgument(struct intr_frame *f, int index)
{
  int arg1;
  memcpy( &arg1, ((int *)(f->esp))+index, sizeof(int));
  return arg1;
}

//Gets the pointer to the argument and makes sure it is not NULL, that it belongs to the user memory and that it is actualled mapped
static int valid_argument(struct intr_frame * f, int index)
{
  int * point = (int *)(f->esp)+index;
  return (point!=NULL && is_user_vaddr(point) && (pagedir_get_page(thread_current()->pagedir, point)!=NULL));
}

struct child_process* add_child(int pid)
{
	struct child_process* cp = malloc(sizeof(struct child_process));
	cp->pid = pid;
	cp->wait = false;
	cp->exit = false;
	list_push_back(&thread_current()->child_list, &cp->elem);
	return cp;
}

struct child_process* get_child(pid)
{
	struct thread * t = thread_current();
	struct list_elem* e;
	struct child_process* cp;
	for(e = list_begin(&t->child_list); e != list_end(&t->child_list); e = list_next(e))
	{
		cp =  list_entry(e, struct child_process, elem);
		if(cp->pid == pid)
		{
			return cp;
		}
	}
	return NULL;
}



void remove_child(struct child_process * cp)
{
	list_remove(&cp->elem);
	free(cp);
}
 
