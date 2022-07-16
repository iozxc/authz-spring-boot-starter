package cn.omisheep.authz.core.tk;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.ToString;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Getter
@ToString
public class Token {

    /**
     * token字符串
     */
    private final String tokenVal;

    /**
     * 用户id
     */
    private final Object userId;

    /**
     * token id
     */
    private final String tokenId;

    /**
     * 过期时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final Date expiredTime;

    /**
     * 颁布时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final Date issueTime;

    /**
     * 登录设备系统类型
     */
    private final String deviceType;

    /**
     * 登录设备id
     */
    private final String deviceId;

    /**
     * token 类型
     */
    private final Type type;

    public enum Type {
        ACCESS("acs", "access", "ACCESS"), REFRESH("rfh", "refresh", "REFRESH");

        final List<String> names;

        Type(String... names) {
            this.names = Arrays.asList(names);
        }

        @JsonCreator
        public static Type fromValue(String text) {
            for (Type type : Type.values()) {
                if (type.name().equalsIgnoreCase(text)) {
                    return type;
                }
                if (type.names.contains(text)) {
                    return type;
                }
            }
            return null;
        }
    }

    public Token(String tokenVal, Object userId, String tokenId, Date issueTime, Date expiredTime, String deviceType, String deviceId, Type type) {
        this.tokenVal    = tokenVal;
        this.userId      = userId;
        this.tokenId     = tokenId;
        this.issueTime   = issueTime;
        this.expiredTime = expiredTime;
        this.deviceType  = deviceType;
        this.deviceId    = deviceId;
        this.type        = type;
    }
}