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
     * id - AccessToken和RefreshToken共用的id，可以理解为IssueToken的id
     */
    private final String id;

    /**
     * token字符串
     */
    private final String token;

    /**
     * 多少时间过期 毫秒
     */
    private final Long expiresIn;

    /**
     * 过期时间戳
     */
    private final Long expiresAt;

    /**
     * 用户id
     */
    private final Object userId;

    /**
     * 客户端id
     */
    private final String clientId;

}
