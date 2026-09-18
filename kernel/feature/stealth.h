#ifndef __KSU_FEATURE_STEALTH_H
#define __KSU_FEATURE_STEALTH_H

#include <linux/types.h>

/**
 * KSU Stealth (隐身模式)
 *
 * - 运行时开关：通过 feature 通道 (KSU_FEATURE_STEALTH) 切换。
 *   开启后由内核收紧以下暴露面：
 *     1. dmesg_restrict = 1  -> 非特权进程无法读取内核日志，
 *        KernelSU 相关的 dmesg 痕迹不再对 App 可见；
 *     2. kptr_restrict   = 2 -> /proc/kallsyms 等接口对非特权进程
 *        隐藏内核符号地址（配合 susfs 的 ksyms 隐藏形成双保险）。
 *   符号通过 kallsyms 解析器获取，built-in 与 LKM 两种模式均可用；
 *   解析失败时内核侧静默降级，由 ksud 通过 /proc/sys 兜底。
 *
 * - 编译期静默：CONFIG_KSU_STEALTH=y 时，klog.h 将 KSU 的
 *   pr_info 全部降级为 pr_debug，内核日志中不出现 KernelSU 字样。
 */

bool ksu_stealth_is_enabled(void);

void ksu_stealth_init(void);
void ksu_stealth_exit(void);

#endif // __KSU_FEATURE_STEALTH_H
