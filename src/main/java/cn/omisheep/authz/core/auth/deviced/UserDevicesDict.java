package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.tk.RefreshToken;
import cn.omisheep.authz.core.tk.TokenPair;
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

    /**
     * 可以单独为【每一类 (by role) 用户】设置登录状态管理方案
     * 若为空，则使用默认的
     *
     * @since 1.2.0
     */
    Map<String, AuthzProperties.UserConfig> roleConfig = new ConcurrentHashMap<>();

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

    void addUser(TokenPair tokenPair, HttpMeta httpMeta);

    // =========================   刷新   ========================= //

    boolean refreshUser(RefreshToken refresh, TokenPair tokenPair);

    // =========================   登出   ========================= //

    void removeDeviceByTokenId(Object userId, String refreshTokenId);

    void removeAllDeviceByUserId(Object userId);

    void removeDeviceByUserIdAndDeviceType(Object userId, String deviceType);

    void removeDeviceByUserIdAndDeviceTypeAndDeviceId(Object userId, String deviceType, String deviceId);

    void removeAllDeviceFromCurrentUser();

    void removeCurrentDeviceFromCurrentUser();

    void removeDeviceFromCurrentUserByDeviceType(String deviceType);

    void removeDeviceFromCurrentUserByDeviceTypeAndDeviceId(String deviceType, String deviceId);

    // =========================   查找   ========================= //

    Device getDevice(Object userId, String deviceType, String deviceId);

    List<Object> listUserId();

    List<Device> listDevicesByUserId(Object userId);

    // =========================   活跃用户   ========================= //

    /**
     * 所有【在线/活跃】用户id
     *
     * @param ms 毫秒数
     * @return 用户id数组
     */
    List<Object> listActiveUsers(long ms);

    /**
     * 某个用户【在线/活跃】 设备
     *
     * @param userId 用户id
     * @param ms     毫秒书
     * @return 【在线/活跃】设备数组
     */
    List<Device> listActiveUserDevices(Object userId, long ms);

    // =========================   other   ========================= //

    void request();

    void deviceClean(Object userId);

    default void changeMaximumSameTypeDeviceCount(Object userId, int count) {
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig
                .computeIfAbsent(userId, r -> new AuthzProperties.UserConfig());
        userConfig.setMaximumSameTypeDeviceCount(count);
        deviceClean(userId);
    }

    default void changeMaximumDeviceTotal(Object userId, int count) {
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


    default String requestKey(AccessToken accessToken) {
        return requestKey(accessToken.getUserId(), accessToken.getRefreshTokenId());
    }

    default String requestKey(Object userId, String refreshTokenId) {
        return Constants.USER_REQUEST_KEY_PREFIX.get() + userId + Constants.SEPARATOR + refreshTokenId;
    }

    default String oauthRequestKey(AccessToken accessToken) {
        return oauthRequestKey(accessToken.getUserId(), accessToken.getRefreshTokenId());
    }

    default String oauthRequestKey(Object userId, String refreshTokenId) {
        return Constants.OAUTH_USER_REQUEST_KEY_PREFIX.get() + userId + Constants.SEPARATOR + refreshTokenId;
    }

    default String key(AccessToken accessToken) {
        return key(accessToken.getUserId(), accessToken.getRefreshTokenId());
    }

    default String key(RefreshToken refreshToken) {
        return key(refreshToken.getUserId(), refreshToken.getTokenId());
    }

    default String key(Object userId, String refreshTokenId) {
        return Constants.USER_DEVICE_KEY_PREFIX.get() + userId + Constants.SEPARATOR + refreshTokenId;
    }

    default String oauthKey(AccessToken accessToken) {
        return oauthKey(accessToken.getUserId(), accessToken.getRefreshTokenId());
    }

    default String oauthKey(RefreshToken refreshToken) {
        return oauthKey(refreshToken.getUserId(), refreshToken.getTokenId());
    }

    default String oauthKey(Object userId, String refreshTokenId) {
        return Constants.OAUTH_USER_DEVICE_KEY_PREFIX.get() + userId + Constants.SEPARATOR + refreshTokenId;
    }

    default boolean equalsDeviceByTypeAndId(Device device, String deviceType, String deviceId) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(), deviceType) && StringUtils.equals(device.getDeviceId(),
                                                                                            deviceId);
    }

    default boolean equalsDeviceById(Device device, Device otherDevice) {
        if (device == null) return false;
        return equalsDeviceById(device, otherDevice.getDeviceId());
    }

    default boolean equalsDeviceById(Device device, String deviceId) {
        if (device == null) return false;
        return device.getDeviceId() != null && StringUtils.equals(device.getDeviceId(), deviceId);
    }

    default boolean equalsDeviceByType(Device device, String deviceType) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(), deviceType);
    }

    default boolean equalsDeviceByTypeOrId(Device device, Device otherDevice) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(),
                                  otherDevice.getDeviceType()) || (device.getDeviceId() != null && StringUtils.equals(
                device.getDeviceId(), otherDevice.getDeviceId())); // null时不参与匹配
    }
}
