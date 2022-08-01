package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.util.LogUtils;

/**
 * 定期GC
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class Pelcron {

    private Pelcron() {
    }

    public static void GC() {
        System.gc();
        Runtime run    = Runtime.getRuntime();
        long    max    = run.maxMemory() / 1024 / 1024; // 最大内存（maxMemory）是通过启动JAVA虚拟机时使用参数-Xmx**m指定的
        long    total  = run.totalMemory() / 1024 / 1024; // 已分配内存（totalMemory）jvm使用的内存都是从本地系统获取的
        long    free   = run.freeMemory() / 1024 / 1024; // 已分配内存中的剩余空间(freeMemory) 这是相对以分配内存（totalMemory）计算的
        long    usable = max - total + free; // 最大可用内存 （usable）这是JVM真正还可以再继续使用的内存
        long    using  = total - free; // 当前使用内存 (using)
        LogUtils.debug("已分配内存 = {}MB  当前使用内存 = {}MB  已分配内存中的剩余空间 = {}MB  最大内存 = {}MB  最大可用内存 = {}MB",
                       total, using, free, max, usable);
    }

}
