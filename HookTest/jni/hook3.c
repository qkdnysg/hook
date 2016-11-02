#include <stdio.h>
#include <stdlib.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>

#define CPSR_T_MASK     ( 1u << 5 )

const char* libc_path = "/system/lib/libc.so";
const int long_size = sizeof(long);

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

void putdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }
}


void* get_module_base(pid_t pid, const char* module_name)//获取模块基址
{
    FILE *fp;
    long addr = 0;//long型占4字节
    char *pch;
    char filename[32];
    char line[1024];

    if (pid == 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");  //

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {//strstr:用于判断字符串str2是否是str1的子串
                pch = strtok( line, "-" );//strtok:以token，此处为“-”，分割字符串，第一次返回第一个结果，后续依次返回分割结果，但后续要将第一个参数由首地址改为NULL!
                addr = strtoul( pch, NULL, 16 );//strtoul:将字符串转换成无符号长整型数

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}


long get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)//sleep_addr = get_remote_addr(pid, libc_path, (void *)sleep);
{
    void* local_handle, *remote_handle;

    local_handle = get_module_base(0, module_name);//获取本进程libc.so模块在内存中的加载地址
    remote_handle = get_module_base(target_pid, module_name);//获取目标进程libc.so模块在内存中的加载地址

    printf("module_base: local[%p], remote[%p]\n", local_handle, remote_handle);

    long ret_addr = (long)((uint32_t)remote_handle + (uint32_t)local_addr - (uint32_t)local_handle);
    //如此看来，函数名（sleep）就代表了其地址，这样的计算顺序更为合适
    printf("remote_addr: [%p]\n", (void*) ret_addr); 

    return ret_addr;//返回sleep函数在target进程中的地址
}

int ptrace_call(pid_t pid, long addr, long *params, uint32_t num_params, struct pt_regs* regs)
{
    uint32_t i;
    for (i = 0; i < num_params && i < 4; i ++) {
        regs->uregs[i] = params[i];
    }
    //
    // push remained params to stack
    //
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        putdata(pid, (long)regs->ARM_sp, (char*)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr;//sleep函数所在地址
    if (regs->ARM_pc & 1) {

        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;//cpsr之T位置1
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;//cpsr之T位置0
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);//会暂时停止目前进程的执行，直到有信号来到或子进程结束。
    							//WUNTRACED 若子进程进入暂停状态，则马上返回，但子进程的结束状态不予以理会。
    while (stat != 0xb7f) {

        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}


void inject(pid_t pid)
{
    struct pt_regs old_regs,regs;//pt_regs寄存器结构体
    long sleep_addr;
    printf("sizeof(long)=%d\n", long_size);//添加的代码，打印long类型所占用字节数

    //save old regs
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);//获取target当前寄存器值
    memcpy(&regs, &old_regs, sizeof(regs));//保存寄存器值至regs

    printf("getting remote sleep_addr:\n");
    sleep_addr = get_remote_addr(pid, libc_path, (void *)sleep);
    
    long parameters[1];
    parameters[0] = 10;
    
    ptrace_call(pid, sleep_addr, parameters, 1, &regs);
    
    //restore old regs
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
}


int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: %s <pid to be traced>\n", argv[0]);
        return 1;
    }
                                                                                                     
    pid_t pid;
    int status;
    pid = atoi(argv[1]);
    
    if(0 != ptrace(PTRACE_ATTACH, pid, NULL, NULL))
    {
        printf("Trace process failed:%d.\n", errno);
        return 1;
    }
    
    inject(pid);
    
    ptrace(PTRACE_DETACH, pid, NULL, 0);
    
    return 0;
}
