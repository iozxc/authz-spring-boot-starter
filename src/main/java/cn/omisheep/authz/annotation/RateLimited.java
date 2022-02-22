package cn.omisheep.authz.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * RateLimit的注解配置
 *
 * @author zhou xin chen
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimited {

    /**
     * 单位 ms|s|m|h|d
     * 规定时间内(默认1秒) 请求数量大于最大数量，则将其禁止。时间默认1h
     *
     * @return -
     */
    String window() default "1s";

    /**
     * 在规定时间内不能重复请求，否则拉入黑名单(禁止对该接口继续请求)，且在规定时间后释放
     *
     * @return -
     */
    int maxRequests() default 5;

    /**
     * 在规定时间后释放，默认1小时
     * 单位 ms|s|m|h|d
     *
     * @return -
     */
    String relieveTime() default "1h";

    /**
     * 限制的最大请求间隔
     * 小于0时不对间隔做限制
     * 单位 ms|s|m|h|d
     *
     * @return -
     */
    String interval() default "0ms";

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
