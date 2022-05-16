package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.TokenPair;

import java.util.List;

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

    // =========================   登入   ========================= //

    boolean addUser(Object userId, TokenPair tokenPair, String deviceType, String deviceId, HttpMeta httpMeta);

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

}
