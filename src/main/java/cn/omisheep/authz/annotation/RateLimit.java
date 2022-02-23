package cn.omisheep.authz.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;

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
     * 被禁止后在规定时间后释放，默认 [5分钟,10分钟,30分钟,1小时]。
     * <p>
     * 在解封之后，若在一个窗口的时间周期内仍然出发封禁机制，那么惩罚等级（0是正常）会增加（依次往后+1），时间按照所给的依次往后，直到最后。
     * 如：{@code "1h","2h"} 当在第一次触发封禁机制时，会禁止1h
     * 当解封之后的一个window时间内，又触发封禁机制。那么会封禁2h。再此触发时，仍然还是2h。
     * <p>
     * 当解封后，若过了window窗口时间，没有再触发，惩罚等级会归零。
     *
     * @return 封禁时间（单位 ms | s | m | h | d）
     */
    String[] punishmentTime() default {"5m", "10m", "30m", "1h"};

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

    /**
     * 检查类型，可以是ip或则用户id，或者同时检查
     *
     * @return 检查类型
     */
    CheckType[] checkType() default {CheckType.IP};

    /**
     * 1. 关联的api.当此api封禁时，该ip或者用户id在其他api同样封禁，支持*
     * <p>
     * 2. 如果需要选择模式，则加上前缀可多个，用空格隔开，方法类型 + 空格
     * <p>
     * 3. 当不加时默认为GET，全加可以用*代替
     * <p>
     * 例子:
     * <pre> * /api/login   --->  GET POST ... /api/login </pre>
     * <pre> /api/log   --->   GET /api/log </pre>
     * <pre> POST /api/login </pre>
     * <pre> POST GET /api/login </pre>
     * <pre> DELETE /api/delete </pre>
     * <pre> GET /api/*  --->  /api下的全部封禁 </pre>
     *
     * @return 关联的api集合
     */
    String[] associatedPatterns() default {};

    enum CheckType {
        IP("ip"),
        USER_ID("USER_ID", "user_id", "userId", "id");

        CheckType(String... names) {
            this.names = names;
        }

        public static CheckType of(String name) {
            for (CheckType value : CheckType.values()) {
                if (Arrays.asList(value.names).contains(name)) {
                    return value;
                }
            }
            return null;
        }

        private final String[] names;
    }

}
