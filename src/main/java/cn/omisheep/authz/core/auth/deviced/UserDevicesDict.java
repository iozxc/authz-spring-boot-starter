package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;

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

    byte SUCCESS         = 0;
    byte REQUIRE_LOGIN   = 1;
    byte LOGIN_EXCEPTION = 2;

    /**
     * 用户设备状态判断，以及L1Cache下的第二次惰性删除
     *
     * @param accessToken token
     * @return 0：正常  1：accessToken过期  2：需要重新登录  3：在别处登录
     */
    byte userStatus(Token accessToken);

    // =========================   登入   ========================= //

    boolean addUser(TokenPair tokenPair, HttpMeta httpMeta);

    // =========================   刷新   ========================= //

    boolean refreshUser(TokenPair tokenPair);

    // =========================   登出   ========================= //

    void removeDeviceByUserIdAndAccessTokenId(Object userId, String accessTokenId);

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

    List<Device> listDevicesForCurrentUser();

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
        DeviceCountInfo deviceCountInfo = new DeviceCountInfo().setTypes(new HashSet<String>(types)).setTotal(total);
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig
                .computeIfAbsent(userId, r -> new AuthzProperties.UserConfig());
        userConfig.getTypesTotal().add(deviceCountInfo);
        deviceClean(userId);
    }

    default List<DeviceCountInfo> getAndUpdateDeviceTypesTotalLimit(Object userId) {
        AuthzProperties.UserConfig userConfig = UserDevicesDict.usersConfig.get(userId);
        if (userConfig == null) return null;
        return userConfig.getTypesTotal();
    }

}
