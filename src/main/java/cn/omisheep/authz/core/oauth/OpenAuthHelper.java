package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.callback.CreateAuthorizationInfoCallback;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.encryption.Digest;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.UUIDBits;
import lombok.Setter;
import org.apache.commons.lang.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static cn.omisheep.authz.core.AuthzManager.cache;
import static cn.omisheep.authz.core.config.Constants.AUTHORIZE_CODE_PREFIX;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class OpenAuthHelper {

    private OpenAuthHelper() {
    }

    private static final AuthzProperties.TokenConfig.OpenAuthConfig oauthConfig     = AUtils.getBean(
            AuthzProperties.class).getToken().getOauth();
    private static final OpenAuthLibrary                            openAuthLibrary = AUtils.getBean(
            OpenAuthLibrary.class);
    @Setter
    private static       CreateAuthorizationInfoCallback            createAuthorizationInfoCallback;

    public static TokenPair authorize(String clientId, String clientSecret,
                                      String authorizationCode) throws AuthorizationException {
        ClientDetails clientDetails = openAuthLibrary.getClientById(clientId);

        if (clientDetails == null || !StringUtils.equals(clientDetails.getClientSecret(), clientSecret)) {
            // 密钥错误
            throw AuthorizationException.clientSecretError();
        }

        String            key               = AUTHORIZE_CODE_PREFIX + authorizationCode;
        AuthorizationInfo authorizationInfo = cache.get(key, AuthorizationInfo.class);
        cache.del(key);

        if (authorizationInfo == null || authorizationInfo.getExpiredTime().before(TimeUtils.now())) {
            // 授权码不存在或过期
            throw AuthorizationException.authorizationCodeExpiredOrNotExist();
        }

        TokenPair tokenPair = TokenHelper.createTokenPair(authorizationInfo);
        if (AuthzDefender.grant(tokenPair)) return null;
        return tokenPair;
    }

    public static String createAuthorizationCode(String clientId, String scope, String redirectUrl,
                                                 Object userId, String deviceType,
                                                 String deviceId) throws AuthorizationException {
        ClientDetails client = findClient(clientId);

        if (client == null || !StringUtils.equals(client.getRedirectUrl(), redirectUrl)) {
            throw AuthorizationException.clientNotExist();
        }

        String authorizationCode = Digest.hash(oauthConfig.getAlgorithm().getValue(),
                                               clientId + scope + System.currentTimeMillis() + UUIDBits.getUUIDBits(
                                                       16));
        if (authorizationCode == null) throw AuthorizationException.privilegeGrantFailed();
        LocalDateTime now     = LocalDateTime.now();
        Date          fromNow = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date expiredTime =
                Date.from(LocalDateTime.now().plus(AuthzAppVersion.authorizationCodeTime, ChronoUnit.MILLIS).atZone(
                        ZoneId.systemDefault()).toInstant());
        AuthorizationInfo authorizationInfo = new AuthorizationInfo(clientId, scope, userId, deviceType, deviceId,
                                                                    fromNow, expiredTime);
        if (createAuthorizationInfoCallback != null) {
            createAuthorizationInfoCallback.createAuthorizationInfoCallback(authorizationCode, authorizationInfo);
        }
        cache.set(AUTHORIZE_CODE_PREFIX + authorizationCode, authorizationInfo,
                  oauthConfig.getAuthorizationCodeTime());
        return authorizationCode;
    }

    public static String createDefaultScopeAuthorizationCode(String clientId, String redirectUrl, Object userId,
                                                             String deviceType,
                                                             String deviceId) throws AuthorizationException {
        return createAuthorizationCode(clientId, oauthConfig.getDefaultScope(), redirectUrl, userId, deviceType,
                                       deviceId);
    }

    public static ClientDetails clientRegister(String clientName, String redirectUrl) {
        String clientId = UUIDBits.getUUIDBits(oauthConfig.getClientIdLength(),
                                               k -> openAuthLibrary.getClientById(k) == null,
                                               20);
        if (clientId == null) return null; // 重复id，重试
        return clientRegister(clientId, UUIDBits.getUUIDBits(oauthConfig.getClientSecretLength()), clientName,
                              redirectUrl);
    }

    public static ClientDetails clientRegister(String clientId, String clientName, String redirectUrl) {
        if (clientId == null) return null;
        return clientRegister(clientId, UUIDBits.getUUIDBits(oauthConfig.getClientSecretLength()), clientName,
                              redirectUrl);
    }

    public static ClientDetails clientRegister(String clientId, String clientSecret, String clientName,
                                               String redirectUrl) {
        if (clientId == null || clientSecret == null) return null;
        ClientDetails clientDetails = new ClientDetails().setClientId(clientId).setClientSecret(clientSecret).setName(
                clientName).setRedirectUrl(redirectUrl);
        openAuthLibrary.registerClient(clientDetails);
        return clientDetails;
    }

    public static ClientDetails findClient(String clientId) {
        if (clientId == null) return null;
        return openAuthLibrary.getClientById(clientId);
    }

    public static void deleteClient(String clientId) {
        if (clientId == null) return;
        openAuthLibrary.deleteClientById(clientId);
    }

}
