package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.encryption.Digest;
import cn.omisheep.commons.util.UUIDBits;
import org.apache.commons.lang.StringUtils;

import static cn.omisheep.authz.core.config.Constants.AUTHORIZE_CODE_PREFIX;
import static cn.omisheep.authz.core.config.Constants.CLINT_PREFIX;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class OpenAuthHelper {

    private OpenAuthHelper() {
    }

    private static final AuthzProperties.TokenConfig.OpenAuthConfig oauthConfig;
    private static final Cache                                      cache = AUtils.getBean(Cache.class);

    static {
        oauthConfig = AUtils.getBean(AuthzProperties.class).getToken().getOauth();
    }

    public static TokenPair authorize(String clientId, String clientSecret,
                                      String authorizationCode) throws AuthorizationException {
        ClientDetails clientDetails = cache.get(CLINT_PREFIX + clientId, ClientDetails.class);
        if (clientDetails == null || !StringUtils.equals(clientDetails.getClientSecret(), clientSecret)) {
            // 密钥错误
            throw AuthorizationException.clientSecretError();
        }
        AuthorizationInfo authorizationInfo = cache.get(AUTHORIZE_CODE_PREFIX + authorizationCode,
                                                        AuthorizationInfo.class);
        if (authorizationInfo == null) {
            // 授权码不存在或过期
            throw AuthorizationException.authorizationCodeExpiredOrNotExist();
        }

        cache.del(AUTHORIZE_CODE_PREFIX + authorizationCode);

        return TokenHelper.createTokenPair(authorizationInfo);
    }

    public static String createAuthorizationCode(String clientId, String scope,
                                                 Object userId, String deviceType, String deviceId) {
        String authorizationCode = Digest.hash(oauthConfig.getAlgorithm().getValue(),
                                               clientId + scope + System.currentTimeMillis() + UUIDBits.getUUIDBits(
                                                       16));
        AuthorizationInfo authorizationInfo = new AuthorizationInfo().setClientId(clientId)
                .setUserId(userId).setDeviceId(deviceId).setDeviceType(
                        deviceType).setScope(scope);
        cache.set(AUTHORIZE_CODE_PREFIX + authorizationCode, authorizationInfo,
                  oauthConfig.getAuthorizationCodeTime());
        return authorizationCode;
    }

    public static ClientDetails clientRegister(String clientName, String redirectUrl) {
        String clientId = UUIDBits.getUUIDBits(24, k -> cache.notKey(CLINT_PREFIX + k), 20);
        if (clientId == null) return null; // 重复id，重试
        return clientRegister(clientId, UUIDBits.getUUIDBits(30), clientName, redirectUrl);
    }

    public static ClientDetails clientRegister(String clientId, String clientName, String redirectUrl) {
        return clientRegister(clientId, UUIDBits.getUUIDBits(30), clientName, redirectUrl);
    }

    public static ClientDetails clientRegister(String clientId, String clientSecret, String clientName,
                                               String redirectUrl) {
        ClientDetails clientDetails = new ClientDetails().setClientId(clientId).setClientSecret(clientSecret).setName(
                clientName).setRedirectUrl(redirectUrl);
        cache.set(CLINT_PREFIX + clientId, clientDetails);
        return clientDetails;
    }

    public static ClientDetails findClient(String clientId) {
        return cache.get(CLINT_PREFIX + clientId, ClientDetails.class);
    }

}
