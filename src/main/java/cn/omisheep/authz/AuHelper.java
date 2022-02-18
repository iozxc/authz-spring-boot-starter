package cn.omisheep.authz;


import cn.omisheep.authz.core.auth.AuthzDefender;
import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.TimeUtils;
import lombok.NonNull;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Au API 集合
 *
 * @author zhou xin chen
 */
public class AuHelper {

    // **************************************     登录      ************************************** //

    /**
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null
     * @return 授权后的tokenPair(accessToken以及refreshToken)
     */
    public static TokenPair login(@NonNull Object userId, @NonNull String deviceType) {
        return login(userId, deviceType, null);
    }

    /**
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null
     * @param deviceId   设备id - 可为null 且为 "" 时于 null等价
     * @return 授权后的tokenPair(accessToken以及refreshToken)
     */
    public static TokenPair login(@NonNull Object userId, @NonNull String deviceType, String deviceId) {
        return auDefender.grant(userId, deviceType, deviceId);
    }

    /**
     * access过期刷新接口。
     * <p>
     * 如果使用单token，则直接使用accessToken即可，在accessToken过期时再重新登录。
     * <p>
     * 使用双token时，accessToken过期时，可以利用refreshToken在此接口中刷新获得一个新的accessToken。
     *
     * @param refreshToken 与accessToken一起授予的refreshToken
     * @return 刷新成功（true）/ 失败（false）
     */
    public static TokenPair refreshToken(String refreshToken) {
        return auDefender.refreshToken(refreshToken);
    }

    // **************************************     用户设备      ************************************** //

    public static Map<Object, List<Device>> listAllUsersDevices() {
        HashMap<Object, List<Device>> map = new HashMap<>();
        for (Object userId : AuHelper.listUserId()) {
            Device[] devices = AuHelper.listDeviceByUserId(userId);
            if (devices != null) {
                map.put(userId, Arrays.asList(devices));
            }
        }
        return map;
    }

    /**
     * 当前访问用户的所有设备
     *
     * @return 所有设备列表
     */
    public static Device[] listDevicesForCurrentUser() {
        return userDevicesDict.listDevicesForCurrentUser();
    }

    /**
     * 退出指定id用户
     *
     * @param userId 用户id
     */
    public static void removeUserById(Object userId) {
        userDevicesDict.removeAllDeviceByUserId(userId);
    }

    /**
     * 退出指定设备id用户
     *
     * @param userId   用户id
     * @param deviceId 设备Id
     */
    public static void removeUserByDeviceId(Object userId, String deviceId) {
        userDevicesDict.removeDeviceByUserIdAndDeviceId(userId, deviceId);
    }

    /**
     * 退出指定设备id用户
     *
     * @param userId     用户id
     * @param deviceType 设备系统类型
     */
    public static void removeUserByDeviceType(Object userId, String deviceType) {
        userDevicesDict.removeDeviceByUserIdAndDeviceType(userId, deviceType);
    }

    /**
     * @return 所有当前有效登录用户的用户id, 当开启redis缓存时，userId返回为String数组
     */
    public static Object[] listUserId() {
        return userDevicesDict.listUserId();
    }

    public static Device[] listDeviceByUserId(Object userId) {
        return userDevicesDict.listDevicesByUserId(userId);
    }

    // **************************************     缓存      ************************************** //


    /**
     * 重新加载所有缓存
     */
    public static void reloadCache() {
        cache.reload();
    }

    // **************************************     ip黑名单      ************************************** //

    // ******************************************     统计      ****************************************** //
//    public static long countView(StatisticalType type, String scope) {
//        HyperLogLog hyperLogLog = AggregateManager.getCmp().get(type).get(scope);
//        if (hyperLogLog != null) return hyperLogLog.cardinality();
//        return 0;
//    }
//
//    public static long countView(StatisticalType type) {
//        return countView(type, "");
//    }

    // ************************************     【在线/活跃】      ************************************ //

    /**
     * 判断某个用户是否有设备【在线/活跃】（默认60秒内），
     *
     * @param userId 用户id
     * @return 用户是否在线
     */
    public static boolean checkUserIsActive(Object userId) {
        return userDevicesDict.listActiveUserDevices(userId, 60000L).length > 0;
    }

    /**
     * 判断某个用户是否有设备【在线/活跃】
     *
     * @param userId 用户id
     * @param time   时间间隔
     * @return 用户是否在线
     */
    public static boolean checkUserIsActive(Object userId, String time) {
        return userDevicesDict.listActiveUserDevices(userId, TimeUtils.parseTimeValue(time)).length > 0;
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户数量
     *
     * @return 用户id数组
     */
    public static int getActiveUsersNumbers() {
        return userDevicesDict.listActiveUsers(60000L).length;
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    public static int getActiveUsersNumbers(String time) {
        return userDevicesDict.listActiveUsers(TimeUtils.parseTimeValue(time)).length;
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户Id数组
     *
     * @return 用户id数组
     */
    public static Object[] listActiveUsers() {
        return userDevicesDict.listActiveUsers(60000L);
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    public static Object[] listActiveUsers(String time) {
        return userDevicesDict.listActiveUsers(TimeUtils.parseTimeValue(time));
    }


    private static final AuthzDefender auDefender;
    private static final UserDevicesDict userDevicesDict;
    private static final Cache cache;

    private AuHelper() {
    }

    static {
        userDevicesDict = AUtils.getBean(UserDevicesDict.class);
        auDefender = AUtils.getBean(AuthzDefender.class);
        cache = AUtils.getBean(Cache.class);
    }
}
