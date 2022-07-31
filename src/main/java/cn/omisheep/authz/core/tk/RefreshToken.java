package cn.omisheep.authz.core.tk;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class RefreshToken {

    /**
     * token字符串
     */
    private final String token;

    /**
     * refresh token id
     */
    private final String tokenId;

    /**
     * 多少时间过期
     */
    private final Integer expiredIn;

    /**
     * 过期时间戳
     */
    private final Long expiredAt;

    /**
     * 用户id
     */
    private final Object userId;

    /**
     * 客户端id
     */
    private final String clientId;

}
