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
public class IssueToken {

    /**
     * access token 的值
     */
    private String accessToken;

    /**
     * refresh token 的值
     */
    private String refreshToken;

    /**
     * 过期时间 毫秒，时间到期请用 refreshToken 刷新获得新的accessToken和refreshToken
     */
    private Long expiresIn;

    /**
     * 授权范围
     */
    private String scope;

}
