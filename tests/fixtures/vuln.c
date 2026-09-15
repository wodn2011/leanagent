/* 样本：栈溢出（ret2win）。编译见 tests/test_smoke.py。
 * gcc -fno-stack-protector -no-pie -o vuln vuln.c   （NX 默认开启）
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* 后门函数：从未被调用，跳到这里即拿到 shell。 */
void win(void) {
    system("/bin/sh");
}

int main(void) {
    char buf[64];
    puts("input:");
    /* 256 远大于 64 → 栈溢出，可覆盖返回地址。 */
    read(0, buf, 256);
    return 0;
}
