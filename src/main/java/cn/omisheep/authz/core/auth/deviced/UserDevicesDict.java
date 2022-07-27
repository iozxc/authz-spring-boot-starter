package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;

import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface UserDevicesDict {

    byte SUCCESS              = 0;
    byte ACCESS_TOKEN_OVERDUE = 1;
    byte REQUIRE_LOGIN        = 2;
    byte LOGIN_EXCEPTION      = 3;

    /**
     * 用户设备状态判断，以及L1Cache下的第二次惰性删除
     *
     * @param accessToken token
     * @return 0：正常  1：accessToken过期  2：需要重新登录  3：在别处登录
     */
    int userStatus(Token accessToken);

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
