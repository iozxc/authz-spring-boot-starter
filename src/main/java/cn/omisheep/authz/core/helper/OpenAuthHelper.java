package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.callback.AuthorizationCallback;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.oauth.AuthorizationException;
import cn.omisheep.authz.core.oauth.AuthorizationInfo;
import cn.omisheep.authz.core.oauth.AuthorizedDeviceDetails;
import cn.omisheep.authz.core.oauth.ClientDetails;
import cn.omisheep.authz.core.tk.GrantType;
import cn.omisheep.authz.core.tk.IssueToken;
import cn.omisheep.authz.core.tk.TokenHelper;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.commons.encryption.Digest;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.commons.util.UUIDBits;
import lombok.Setter;
import org.apache.commons.lang.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.config.Constants.AUTHORIZE_CODE_PREFIX;
import static cn.omisheep.authz.core.config.Constants.WILDCARD;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class OpenAuthHelper extends BaseHelper {

    private OpenAuthHelper() {
        throw new UnsupportedOperationException();
    }

    private static final AuthzProperties.OpenAuthConfig oauthConfig = properties.getOauth();

    @Setter
    private static AuthorizationCallback authorizationCallback;

    public static IssueToken authorizeByCode(String clientId,
                                             String clientSecret,
                                             String authorizationCode) throws AuthorizationException {
        checkClient(clientId, clientSecret);

        String            key               = AUTHORIZE_CODE_PREFIX.get() + authorizationCode;
        AuthorizationInfo authorizationInfo = cache.get(key, AuthorizationInfo.class);
        cache.del(key);

        if (authorizationInfo == null || authorizationInfo.getExpiresAt() < TimeUtils.nowTime()) {
            // 授权码不存在或过期
            throw AuthorizationException.authorizationCodeExpiredOrNotExist();
        }

        return authorize(authorizationInfo);
    }

    public static IssueToken authorizeByPassword(String clientId,
                                                 String clientSecret,
                                                 String scope,
                                                 Object userId) throws AuthorizationException {
        ClientDetails clientDetails = checkClient(clientId, clientSecret);

        if (userId == null) throw AuthorizationException.privilegeGrantFailed();
        AuthorizationInfo authorizationInfo = new AuthorizationInfo(clientId, clientDetails.getClientName(), scope,
                                                                    GrantType.PASSWORD, null, null, null, userId);

        return authorize(authorizationInfo);
    }

    public static IssueToken authorizeByClient(String clientId,
                                               String clientSecret,
                                               String scope) throws AuthorizationException {
        ClientDetails clientDetails = checkClient(clientId, clientSecret);

        AuthorizationInfo authorizationInfo = new AuthorizationInfo(clientId, clientDetails.getClientName(), scope,
                                                                    GrantType.CLIENT_CREDENTIALS, null, null,
                                                                    null, null);

        return authorize(authorizationInfo);
    }

    private static ClientDetails checkClient(String clientId,
                                             String clientSecret) throws AuthorizationException {
        ClientDetails clientDetails = openAuthLibrary.getClientById(clientId);

        if (clientDetails == null || !StringUtils.equals(clientDetails.getClientSecret(), clientSecret)) {
            // 密钥错误
            throw AuthorizationException.clientSecretError();
        }
        return clientDetails;
    }

    private static IssueToken authorize(AuthorizationInfo authorizationInfo) {
        TokenPair tokenPair = TokenHelper.createTokenPair(authorizationInfo);
        if (!AuthzGranterHelper.grant(tokenPair, false)) return null;

        if (authorizationCallback != null) {
            authorizationCallback.authorize(
                    new AuthorizedDeviceDetails(authorizationInfo, tokenPair.getRefreshToken().getId()));
        }
        return TokenHelper.createIssueToken(tokenPair);
    }

    public static String createAuthorizationCode(String clientId,
                                                 String scope,
                                                 String redirectUrl,
                                                 Object userId) throws AuthorizationException {
        ClientDetails client = findClient(clientId);

        if (client == null || !StringUtils.equals(client.getRedirectUrl(), redirectUrl)) {
            throw AuthorizationException.clientNotExist();
        }

        String authorizationCode = Digest.hash(oauthConfig.getAlgorithm().getValue(),
                                               clientId + scope + System.currentTimeMillis() + UUIDBits.getUUIDBits(
                                                       16));
        if (authorizationCode == null) throw AuthorizationException.privilegeGrantFailed();
        Date now         = TimeUtils.now();
        Date expiredTime = TimeUtils.datePlus(now, AuthzAppVersion.AUTHORIZATION_CODE_TIME.get());

        AuthorizationInfo authorizationInfo = new AuthorizationInfo(clientId, client.getClientName(), scope,
                                                                    GrantType.AUTHORIZATION_CODE,
                                                                    AuthzAppVersion.AUTHORIZATION_CODE_TIME.get(),
                                                                    expiredTime.getTime(), now.getTime(), userId);
        if (authorizationCallback != null) {
            authorizationCallback.createAuthorizationCodeCallback(authorizationCode, authorizationInfo);
        }
        cache.set(AUTHORIZE_CODE_PREFIX.get() + authorizationCode, authorizationInfo,
                  AuthzAppVersion.AUTHORIZATION_CODE_TIME.get());
        return authorizationCode;
    }

    public static String createBasicScopeAuthorizationCode(String clientId,
                                                           String redirectUrl,
                                                           Object userId) throws AuthorizationException {
        return createAuthorizationCode(clientId, oauthConfig.getDefaultBasicScope(), redirectUrl, userId);
    }

    public static ClientDetails clientRegister(String clientName,
                                               String redirectUrl) {
        String clientId = UUIDBits.getUUIDBits(oauthConfig.getClientIdLength(),
                                               k -> openAuthLibrary.getClientById(k) == null, 20);
        if (clientId == null) return null; // 重复id，重试
        return clientRegister(clientId, UUIDBits.getUUIDBits(oauthConfig.getClientSecretLength()), clientName,
                              redirectUrl);
    }

    public static ClientDetails clientRegister(String clientId,
                                               String clientName,
                                               String redirectUrl) {
        if (clientId == null) return null;
        return clientRegister(clientId, UUIDBits.getUUIDBits(oauthConfig.getClientSecretLength()), clientName,
                              redirectUrl);
    }

    public static ClientDetails clientRegister(String clientId,
                                               String clientSecret,
                                               String clientName,
                                               String redirectUrl) {
        if (clientId == null || clientSecret == null) return null;
        ClientDetails clientDetails = new ClientDetails().setClientId(clientId).setClientSecret(
                clientSecret).setClientName(clientName).setRedirectUrl(redirectUrl);
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

    public static List<AuthorizedDeviceDetails> getAllAuthorizedDeviceDetails(Object userId) {
        Set<String>         keys      = cache.keys(UserDevicesDict.oauthKey(userId, Constants.WILDCARD));
        Map<String, Device> deviceMap = cache.get(keys, Device.class);
        Iterator<String>    iterator  = keys.stream().map(k -> k.split(Constants.SEPARATOR)[6]).iterator();
        return deviceMap.values().stream().map(v -> {
            if (v == null) return null;
            return new AuthorizedDeviceDetails(v, userId, iterator.next());
        }).filter(Objects::nonNull).collect(Collectors.toList());
    }

    public static void removeAuthorizedDevice(Object userId,
                                              String authorizedDeviceId) {
        if (authorizedDeviceId.contains(WILDCARD)) return;
        cache.del(UserDevicesDict.oauthKey(userId, authorizedDeviceId));
    }

    public static void removeAllAuthorizedDevice(Object userId) {
        Set<String> keys = cache.keys(UserDevicesDict.oauthKey(userId, Constants.WILDCARD));
        cache.del(keys);
        if (authorizationCallback != null) {
            for (String k : keys) {
                authorizationCallback.removeAuthorization(k.split(Constants.SEPARATOR)[6]);
            }
        }
    }

}
