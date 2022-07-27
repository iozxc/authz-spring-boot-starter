package cn.omisheep.authz.core.callback;

import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import org.springframework.lang.NonNull;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@FunctionalInterface
@SuppressWarnings("all")
public interface CreateAuthorizationInfoCallback {
    /**
     * @param authorizationCode 授权码
     * @param authorizationInfo 成功授权信息
     */
    void createAuthorizationInfoCallback(@NonNull String authorizationCode,
                                         @NonNull AuthorizationInfo authorizationInfo);
}
