package cn.omisheep.authz.core.tk;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccessToken {

    /**
     * token字符串
     */
    private final String token;

    /**
     * access token id
     */
    private final String tokenId;


    /**
     * refresh token id
     */
    private final String refreshTokenId;

    /**
     * 多少时间过期
     */
    private final Integer expiresIn;

    /**
     * 过期时间戳
     */
    private final Long expiresAt;


    /**
     * 授权类型
     */
    private final GrantType grantType;

    /**
     * 客户端id
     */
    private final String clientId;

    /**
     * 权限范围
     */
    private final String scope;

    /**
     * 用户id
     */
    private final Object userId;

    /**
     * 登录设备系统类型
     */
    private final String deviceType;

    /**
     * 登录设备id
     */
    private final String deviceId;

}
