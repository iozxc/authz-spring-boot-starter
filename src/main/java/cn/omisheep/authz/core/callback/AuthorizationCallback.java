package cn.omisheep.authz.core.callback;

import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import org.springframework.lang.NonNull;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@SuppressWarnings("all")
@FunctionalInterface
public interface AuthorizationCallback {

    /**
     * 成功授权时的回调方法
     *
     * @param authorizationInfo 授权信息
     */
    void authorize(@NonNull AuthorizationInfo authorizationInfo);

    /**
     * 授权时的回调方法
     *
     * @param authorizationCode 授权码
     * @param authorizationInfo 授权信息
     */
    default void createAuthorizationCodeCallback(@NonNull String authorizationCode,
                                                 @NonNull AuthorizationInfo authorizationInfo) {
    }

}