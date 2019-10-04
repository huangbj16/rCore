# 实验一：rcore代码注释和测试实验

计63 黄冰鉴 2016011296

2019/10/4

---



我的分析主要是从badarg这个测例出发，对waitpid，fork，以及cprintf进行了错误分析以及修正。



### 分析

#### 发现问题

badarg源码如下：

```c
#include <stdio.h>
#include <ulib.h>

int
main(void) {
    int pid, exit_code;
    if ((pid = fork()) == 0) {
        cprintf("fork ok.\n");
        int i;
        for (i = 0; i < 10; i ++) {
            yield();
        }
        exit(0xbeaf);
    }
    assert(pid > 0);
    assert(waitpid(-1, NULL) != 0);
    assert(waitpid(pid, (void *)0xC0000000) != 0);
    assert(waitpid(pid, &exit_code) == 0 && exit_code == 0xbeaf);
    cprintf("badarg pass.\n");
    return 0;
}
```

badarg运行之后，显示```assert(waitpid(pid, &exit_code) == 0 && exit_code == 0xbeaf);```不成立。对此，刘丰源的解释是：rCore 采用 Linux ABI 标准，wait(-1, store) 会 wait any child ，ucore 会 return -E_BAD_PROC。

我尝试增加了一些调试输出（cprintf）之后，发现事情不太对劲，输出完全是混乱的，很多行交错在一起了，同时pid也显示是一个非常大的数，我意识到出错的原因比较复杂，需要细致的分析。

#### 分析问题

- fork的问题

首先我怀疑是fork的时候出了问题，因为cprintf输出的pid不太正常。

我沿着fork的调用关系找，SYS_clone -> 56 = SYS_CLONE ->(kernel) sys_clone -> sys_fork，并没有发现问题。

接着我在编译选项中增加了Log=info，通过调试输出看到```INFO][1][rcore::syscall::proc] fork: 1 -> 2```，说明fork是成功的，而且创建的子进程pid=2，没有问题。

- cprintf的问题

既然fork没有问题，那应该是因为cprintf自身的问题，将pid解析成了非常大的一个整数。

cprintf的调用关系是cprintf -> vcprintf -> vprintfmt -> cputch -> fputch -> write sys_write -> syscall (SYS_write = 1) -> dispatch -> syscall -> sys_write(fs.rs) -> file_like.write()

问题出在vprintfmt每输出一个字符都要调用一次syscall，而因为syscall可能被其它中断（如时钟中断）打断，导致多个syscall并不是按照时间顺序执行的，只有一个syscall打印的字符串才能保证是顺序的。

在和王润基助教交流过之后，我给vprintfmt和fputch增加了buffer，当读到\0时再一次性调用syscall，输出完整的字符串。

增加buffer之后，每一行输出没有再出现混杂在一起的问题，但是pid输出仍然有问题。我对比了libc vprintfmt的代码和Linux官方的printf实现，发现libc的实现过于简单了，有很多format的细节都没有注意到。我根据规范，将Linux官方的实现移植到了libc中，并手动添加了依赖的函数(isdigit等)，得到了正确的输出结果。

![1570171824125](C:\Users\k_sir\AppData\Roaming\Typora\typora-user-images\1570171824125.png)

- waitpid的问题

waitpid的调用关系是sys_wait -> sys_call (SYS_wait = 61) -> asm volatile(内嵌汇编) ->(kernel) dispatch -> syscall -> sys_wait4，sys_wait4源码如下，

```rust
pub fn sys_wait4(&mut self, pid: isize, wstatus: *mut i32) -> SysResult {
        info!("wait4: pid: {}, code: {:?}", pid, wstatus);
        let wstatus = if !wstatus.is_null() {
            Some(unsafe { self.vm().check_write_ptr(wstatus)? })
        } else {
            None
        };
        #[derive(Debug)]
        enum WaitFor {
            AnyChild,
            AnyChildInGroup,
            Pid(usize),
        }
        let target = match pid {
            -1 => WaitFor::AnyChild,
            0 => WaitFor::AnyCwhildInGroup,
            p if p > 0 => WaitFor::Pid(p as usize),
            _ => unimplemented!(),
        };
        loop {
            let mut proc = self.process();
            // check child_exit_code
            let find = match target {
                WaitFor::AnyChild | WaitFor::AnyChildInGroup => proc
                    .child_exit_code
                    .iter()
                    .next()
                    .map(|(&pid, &code)| (pid, code)),
                WaitFor::Pid(pid) => proc.child_exit_code.get(&pid).map(|&code| (pid, code)),
            };
            // if found, return
            if let Some((pid, exit_code)) = find {
                proc.child_exit_code.remove(&pid);
                if let Some(wstatus) = wstatus {
                    *wstatus = exit_code as i32;
                }
                return Ok(pid);
            }
            // if not, check pid
            let invalid = {
                let children: Vec<_> = proc
                    .children
                    .iter()
                    .filter_map(|weak| weak.upgrade())
                    .collect();
                match target {
                    WaitFor::AnyChild | WaitFor::AnyChildInGroup => children.len() == 0,
                    WaitFor::Pid(pid) => children
                        .iter()
                        .find(|p| p.lock().pid.get() == pid)
                        .is_none(),
                }
            };
            if invalid {
                return Err(SysError::ECHILD);
            }
            info!(
                "wait: thread {} -> {:?}, sleep",
                thread::current().id(),
                target
            );
            let condvar = proc.child_exit.clone();
            condvar.wait(proc);
        }
    }
```

在修改了cprintf之后，我发现waitpid的返回其实是2，也就是子进程的pid，而不是assert的0。在查看Linux规范后我发现，返回pid是正确的。而之所以无法通过ucore的test，是因为ucore的waitpid不是标准实现，规范不同。

至此，我认为badarg的分析已经足够细致了，并且我解决了我能解决的问题。



### References

<https://github.com/torvalds/linux/blob/master/arch/x86/boot/printf.c>

<https://github.com/torvalds/linux/blob/master/include/linux/ctype.h> contain "isdigit"

<https://www.tutorialspoint.com/c_standard_library/c_function_vsprintf.htm> description of vsprintf