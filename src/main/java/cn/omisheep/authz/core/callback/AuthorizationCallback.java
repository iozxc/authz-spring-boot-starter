package cn.omisheep.authz.core.callback;

import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import cn.omisheep.authz.core.oauth.AuthorizedDeviceDetails;
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
     * @param authorizedDeviceDetails 授权信息
     */
    void authorize(@NonNull AuthorizedDeviceDetails authorizedDeviceDetails);

    /**
     * 删除授权时的回调方法
     *
     * @param id 授权信息id
     */
    default void removeAuthorization(@NonNull String id) {

    }

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