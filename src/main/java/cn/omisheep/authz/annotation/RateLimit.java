package cn.omisheep.authz.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * RateLimit 的注解配置，也可以使用json配置来完成对于某个api的配置或者对全局进行配置
 * json 配置如下：
 * <pre>
 *     {
 *         "zxc": "admin"
 *     }
 * </pre>
 * <p>
 * 【注：网关上的配置一样生效】
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {

    /**
     * 规定时间段内(默认1秒) 请求数量大于最大数量{@link #maxRequests()}，则将其禁止。
     * <p>
     * 禁止时间{@link #punishmentTime()}默认1h
     *
     * @return 时间窗口（单位 ms | s | m | h | d）
     */
    String window() default "1s";

    /**
     * 在规定的时间窗口内的最大请求数量，超出范围则拉入黑名单(禁止对该接口继续请求)
     *
     * @return 在时间窗口内，最大的请求数量
     */
    int maxRequests() default 5;

    /**
     * 被禁止后在规定时间后释放，默认1小时
     *
     * @return 封禁时间（单位 ms | s | m | h | d）
     */
    String punishmentTime() default "1h";

    /**
     * 最小请求间隔，小于等于0时不对间隔做限制
     *
     * @return 最小请求间隔（单位 ms | s | m | h | d）
     */
    String minInterval() default "0ms";

    /**
     * 封禁角色时，是针对某个接口来说的封禁还是全局的封禁
     * <p>
     * API 针对接口
     * IP 全局封禁
     *
     * @return -
     */
    BannedType bannedType() default BannedType.API;
}
