#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/version.h>

#include "feature/stealth.h"
#include "klog.h" // IWYU pragma: keep
#include "infra/symbol_resolver.h"
#include "policy/feature.h"

struct ksu_stealth_sysctl {
    const char *name;
    int enable_value; // 隐身开启时写入的值
    int *addr;        // kallsyms 解析出的符号地址
    bool resolved;
    bool has_restore_value;
    int restore_value;
};

/*
 * 通过 kallsyms 解析内核 printk 的全局开关，避免直接 extern
 * （这两个符号没有 EXPORT_SYMBOL，LKM 模式下无法直接链接）。
 * 解析不到（如 CONFIG_KALLSYMS_ALL=n）时 resolved=false，
 * 内核侧静默降级，由 ksud 写 /proc/sys 兜底。
 */
static struct ksu_stealth_sysctl stealth_sysctls[] = {
    { .name = "dmesg_restrict", .enable_value = 1, .addr = NULL, .resolved = false,
      .has_restore_value = false, .restore_value = 0 },
    { .name = "kptr_restrict", .enable_value = 2, .addr = NULL, .resolved = false,
      .has_restore_value = false, .restore_value = 0 },
};

static bool ksu_stealth_enabled __read_mostly = false;

bool ksu_stealth_is_enabled(void)
{
    return ksu_stealth_enabled;
}

static void stealth_sysctl_apply(bool enable)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(stealth_sysctls); i++) {
        struct ksu_stealth_sysctl *s = &stealth_sysctls[i];

        if (!s->resolved || s->addr == NULL) {
            continue;
        }

        if (enable) {
            if (!s->has_restore_value) {
                s->restore_value = READ_ONCE(*s->addr);
                s->has_restore_value = true;
            }
            WRITE_ONCE(*s->addr, s->enable_value);
            pr_info("stealth: %s -> %d\n", s->name, s->enable_value);
        } else if (s->has_restore_value) {
            WRITE_ONCE(*s->addr, s->restore_value);
            pr_info("stealth: %s restored to %d\n", s->name, s->restore_value);
        }
    }
}

static int stealth_feature_get(u64 *value)
{
    *value = ksu_stealth_enabled ? 1 : 0;
    return 0;
}

static int stealth_feature_set(u64 value)
{
    bool enable = value != 0;

    if (ksu_stealth_enabled == enable) {
        return 0;
    }

    stealth_sysctl_apply(enable);
    ksu_stealth_enabled = enable;

    pr_info("stealth: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler stealth_handler = {
    .feature_id = KSU_FEATURE_STEALTH,
    .name = "stealth",
    .get_handler = stealth_feature_get,
    .set_handler = stealth_feature_set,
};

void __init ksu_stealth_init(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(stealth_sysctls); i++) {
        struct ksu_stealth_sysctl *s = &stealth_sysctls[i];
        unsigned long addr = find_kernel_symbol_exact(s->name);

        if (addr) {
            s->addr = (int *)addr;
            s->resolved = true;
        } else {
            s->addr = NULL;
            s->resolved = false;
            // 注意：隐身模式下不应在 dmesg 留下 KSU 字样，此处用 pr_debug
            pr_debug("stealth: symbol %s not found, kernel-side hardening disabled\n", s->name);
        }
    }

    if (ksu_register_feature_handler(&stealth_handler)) {
        pr_err("Failed to register stealth feature handler\n");
    }
}

void __exit ksu_stealth_exit(void)
{
    if (ksu_stealth_enabled) {
        stealth_sysctl_apply(false);
        ksu_stealth_enabled = false;
    }
    ksu_unregister_feature_handler(KSU_FEATURE_STEALTH);
}
