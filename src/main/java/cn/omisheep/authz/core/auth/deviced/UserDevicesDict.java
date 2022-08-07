package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.*;
import org.apache.commons.lang.StringUtils;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface UserDevicesDict {

    /**
     * 可以单独为【每一名用户】设置登录状态管理方案
     * 若为空，则使用默认的
     *
     * @since 1.2.0
     */
    Map<Object, AuthzProperties.UserConfig> usersConfig = new ConcurrentHashMap<>();

    enum UserStatus {
        SUCCESS, REQUIRE_LOGIN, LOGIN_EXCEPTION, ACCESS_TOKEN_OVERDUE;
    }

    /**
     * 用户设备状态判断，以及L1Cache下的第二次惰性删除
     *
     * @param accessToken token
     * @return {@link UserStatus}
     */
    UserStatus userStatus(AccessToken accessToken);

    // =========================   登入   ========================= //

    void addUser(TokenPair tokenPair,
                 HttpMeta httpMeta);

    // =========================   刷新   ========================= //

    boolean refreshUser(RefreshToken refresh,
                        TokenPair tokenPair);

    // =========================   登出   ========================= //

    void removeAccessTokenByTid(Object userId,
                                String tid);

    void removeDeviceById(Object userId,
                          String tid);

    void removeDevice(Object userId,
                      String deviceType,
                      String deviceId);

    void removeAllDevice(Object userId);

    void removeCurrentDevice();

    // =========================   查找   ========================= //

    boolean isLogin(Object userId,
                    String id);

    DeviceDetails getDevice(Object userId,
                            String deviceType,
                            String deviceId);

    List<Object> listUserId();

    List<DeviceDetails> listDevicesByUserId(Object userId);

    // =========================   活跃用户   ========================= //

    /**
     * 所有用户【在线/活跃】 设备
     *
     * @param ms 毫秒数
     * @return 【在线/活跃】设备数组
     */
    List<DeviceDetails> listActiveUserDevices(long ms);

    /**
     * 某个用户的【在线/活跃】 设备
     *
     * @param ms 毫秒数
     * @return 【在线/活跃】设备数组
     */
    List<DeviceDetails> listActiveUserDevices(Object userId,
                                              long ms);

    // =========================   other   ========================= //

    void request(HttpMeta httpMeta);

    void deviceClean(Object userId);

    default void changeMaximumSameTypeDeviceCount(Object userId,
                                                  int count) {
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig
                .computeIfAbsent(userId, r -> new AuthzProperties.UserConfig());
        userConfig.setMaximumSameTypeDeviceCount(count);
        deviceClean(userId);
    }

    default void changeMaximumDeviceTotal(Object userId,
                                          int count) {
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig
                .computeIfAbsent(userId, r -> new AuthzProperties.UserConfig());
        userConfig.setMaximumTotalDevice(count);
        deviceClean(userId);
    }

    default void addDeviceTypesTotalLimit(Object userId,
                                          Collection<String> types,
                                          int total) {
        DeviceCountInfo deviceCountInfo = new DeviceCountInfo().setTypes(new HashSet<>(types)).setTotal(total);
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig
                .computeIfAbsent(userId, r -> new AuthzProperties.UserConfig());
        userConfig.getTypesTotal().add(deviceCountInfo);
        deviceClean(userId);
    }

    default List<DeviceCountInfo> getOrUpdateDeviceTypesTotalLimit(Object userId) {
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig.get(userId);
        if (userConfig == null) return null;
        return userConfig.getTypesTotal();
    }


    static String requestKey(AccessToken accessToken) {
        return requestKey(accessToken.getUserId(), accessToken.getId());
    }

    static String requestKey(Object userId,
                             String tid) {
        return Constants.USER_REQUEST_KEY_PREFIX.get() + userId + Constants.SEPARATOR + tid;
    }

    static String key(AccessToken accessToken) {
        return key(accessToken.getUserId(), accessToken.getId());
    }

    static String key(RefreshToken refreshToken) {
        return key(refreshToken.getUserId(), refreshToken.getId());
    }

    static String key(Object userId,
                      String tid) {
        return Constants.USER_DEVICE_KEY_PREFIX.get() + userId + Constants.SEPARATOR + tid;
    }

    static String oauthKey(AccessToken accessToken) {
        return oauthKey(accessToken.getUserId(), accessToken.getId());
    }

    static String oauthKey(Object userId,
                           String tid) {
        return Constants.OAUTH_USER_DEVICE_KEY_PREFIX.get() + userId + Constants.SEPARATOR + tid;
    }

    static boolean equalsDeviceByTypeAndId(Device device,
                                           String deviceType,
                                           String deviceId) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(), deviceType) && StringUtils.equals(device.getDeviceId(),
                                                                                            deviceId);
    }

}
