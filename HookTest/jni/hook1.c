#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>

long getSysCallNo(int pid, struct pt_regs *regs)
{
    long scno = 0;
    scno = ptrace(PTRACE_PEEKTEXT, pid, (void *)(regs->ARM_pc - 4/*当前执行的指令地址*/), NULL);
    if(scno == 0)
        return 0;
         
    if (scno == 0xef000000) {//[EABI] 机器码：1110 1111 0000 0000 -- SWI 0：具体的调用号存放在寄存器r7中.
        scno = regs->ARM_r7;
    } else {
        if ((scno & 0xfff00000) != 0xdf900000) {//此处说明需要scno=0x yf9yyyyy
            return -1;
        }
        scno &= 0x000fffff;
    }
    return scno;    
}

void hookSysCallBefore(pid_t pid)
{
    struct pt_regs regs;
    int sysCallNo = 0;
    
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);    
    sysCallNo = getSysCallNo(pid, &regs);
    printf("Before SysCallNo = %d\n",sysCallNo);
    
    if(sysCallNo == __NR_write)
    {
        printf("__NR_write: %ld %p %ld\n",regs.ARM_r0,(void*)regs.ARM_r1,regs.ARM_r2);
        //%ld=long
        //printf函数族中对于%p一般以十六进制整数方式输出指针的值，附加前缀0x。
    }
}

void hookSysCallAfter(pid_t pid)
{
    struct pt_regs regs;
    int sysCallNo = 0;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);  
    sysCallNo = getSysCallNo(pid, &regs);
    
    printf("After SysCallNo = %d\n",sysCallNo);
    
    if(sysCallNo == __NR_write)
    {
        printf("__NR_write return: %ld\n",regs.ARM_r0);
    }
    
    printf("\n");
}

int main(int argc, char *argv[])
{
    if(argc != 2) {//使用方法 ./hook1 $pid
        printf("Usage: %s <pid to be traced>\n", argv[0]);
        return 1;
    }
                                                                                                     
    pid_t pid;
    int status;
    pid = atoi(argv[1]);//将字符串型转为整型
    
    if(0 != ptrace(PTRACE_ATTACH, pid, NULL, NULL))
    {//成功返回0。错误返回-1。errno被设置。
        printf("Trace process failed:%d.\n", errno);
        return 1;
    }
    //PTRACE_ATTACH成功，则目标进程成为当前进程的子进程，并进入中止状态，即target此时中止
    //被跟踪进程（target）继续运行，直到系统调用开始或结束时，被跟踪进程被中止，并通知父进程。
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);//即此句执行完后，target中止于系统调用开始时
    
    while(1)
    {
        wait(&status);//等待target完全中止
        hookSysCallBefore(pid);
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        
        wait(&status);
        hookSysCallAfter(pid);
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
    
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
