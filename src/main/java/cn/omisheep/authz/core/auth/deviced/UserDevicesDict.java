package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.TokenPair;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface UserDevicesDict {

    short SUCCESS = 0;
    short ACCESS_TOKEN_OVERDUE = 1;
    short REQUIRE_LOGIN = 2;
    short LOGIN_EXCEPTION = 3;

    /**
     * 用户设备状态判断，以及第二次惰性删除
     *
     * @param userId        用户id
     * @param deviceType    设备系统类型
     * @param deviceId      设备id
     * @param accessTokenId accessTokenId
     * @return 0：正常  1：accessToken过期  2：需要重新登录  3：在别处登录
     */
    int userStatus(Object userId, String deviceType, String deviceId, String accessTokenId);

    boolean addUser(Object userId, TokenPair tokenPair, String deviceType, String deviceId, HttpMeta httpMeta);

    boolean refreshUser(TokenPair tokenPair);

    // =========================   登出   ========================= //

    void removeAllDeviceByUserId(Object userId);

    void removeAllDeviceByCurrentUser();

    void removeDeviceByUserIdAndAccessTokenId(Object userId, String accessTokenId);

    void removeDeviceByCurrentUserAndAccessTokenId(String accessTokenId);

    void removeDeviceByUserIdAndDeviceType(Object userId, String deviceType);

    void removeDeviceByCurrentUserAndDeviceType(String deviceType);

    void removeDeviceByUserIdAndDeviceId(Object userId, String deviceId);

    void removeDeviceByCurrentUserAndDeviceId(String deviceId);

    // =========================   查找   ========================= //

    Device getDevice(Object userId, String deviceType, String deviceId);

    Object[] listUserId();

    Device[] listDevicesByUserId(Object userId);

    Device[] listDevicesForCurrentUser();

    /**
     * 所有【在线/活跃】用户id
     *
     * @param ms 毫秒数
     * @return 用户id数组
     */
    Object[] listActiveUsers(long ms);

    /**
     * 某个用户【在线/活跃】 设备
     *
     * @param userId 用户id
     * @param ms     毫秒书
     * @return 【在线/活跃】设备数组
     */
    Device[] listActiveUserDevices(Object userId, long ms);

    // =========================   other   ========================= //

    void request();

}
