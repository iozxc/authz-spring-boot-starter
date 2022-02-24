package cn.omisheep.authz.core.tk;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@AllArgsConstructor
@Getter
public class TokenPair {

    private final Token accessToken;
    private final Token refreshToken;

}
