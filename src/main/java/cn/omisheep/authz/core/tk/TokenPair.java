package cn.omisheep.authz.core.tk;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@AllArgsConstructor
@Getter
public class TokenPair {

    private final Token accessToken;
    private final Token refreshToken;

}
