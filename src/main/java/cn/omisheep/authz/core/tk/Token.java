package cn.omisheep.authz.core.tk;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.ToString;

import java.util.Date;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
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
    @JsonIgnore
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
    @JsonIgnore
    private final String deviceType;

    /**
     * 登录设备id
     */
    @JsonIgnore
    private final String deviceId;

    /**
     * token 类型
     */
    private final Type type;

    public enum Type {
        access,
        refresh
    }

    public Token(String tokenVal, Object userId, String tokenId, Date issueTime, Date expiredTime, String deviceType, String deviceId, Type type) {
        this.tokenVal = tokenVal;
        this.userId = userId;
        this.tokenId = tokenId;
        this.issueTime = issueTime;
        this.expiredTime = expiredTime;
        this.deviceType = deviceType;
        this.deviceId = deviceId;
        this.type = type;
    }
}