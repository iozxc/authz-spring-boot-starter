package cn.omisheep.authz.core.tk;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@AllArgsConstructor
@Getter
public class TokenPair {
    private final AccessToken  accessToken;
    private final RefreshToken refreshToken;
}
