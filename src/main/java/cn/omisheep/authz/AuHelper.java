package cn.omisheep.authz;


import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.auth.ipf.RequestMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.tk.AuKey;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.Authz.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuHelper {

    // **************************************     登录 & 用户设备      ************************************** //

    /**
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null
     * @return 授权后的tokenPair(accessToken以及refreshToken)，返回空则登录失败
     */
    @Nullable
    public static TokenPair login(@NonNull Object userId, @NonNull String deviceType) {
        return login(userId, deviceType, null);
    }

    /**
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null
     * @param deviceId   设备id - 可为null 且为 "" 时于 null等价
     * @return 授权后的tokenPair(accessToken以及refreshToken)，返回空则登录失败
     */
    @Nullable
    public static TokenPair login(@NonNull Object userId, @NonNull String deviceType, @Nullable String deviceId) {
        return auDefender.grant(userId, deviceType, deviceId);
    }

    /**
     * 注销当前用户当前设备
     */
    public static void logout() {
        userDevicesDict.removeCurrentDeviceFromCurrentUser();
    }

    /**
     * 注销当前用户所有设备
     */
    public static void logoutAll() {
        userDevicesDict.removeAllDeviceFromCurrentUser();
    }


    /**
     * 注销当前用户所指定的类型的所有设备
     *
     * @param deviceType 指定设备类型
     */
    public static void logout(@NonNull String deviceType) {
        userDevicesDict.removeDeviceFromCurrentUserByDeviceType(deviceType);
    }

    /**
     * 注销当前用户所指定的类型和id的设备
     *
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void logout(@NonNull String deviceType, @Nullable String deviceId) {
        userDevicesDict.removeDeviceFromCurrentUserByDeviceTypeAndDeviceId(deviceType, deviceId);
    }

    /**
     * 注销指定用户所有设备，建议用于管理员，如果某用户想通过自己id注销自己，建议加上参数权限判断
     *
     * @param userId 用户id
     */
    public static void logoutAll(@NonNull Object userId) {
        userDevicesDict.removeAllDeviceByUserId(userId);
    }

    /**
     * 注销指定用户所指定的类型的所有设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     */
    public static void logout(@NonNull Object userId, @NonNull String deviceType) {
        userDevicesDict.removeDeviceByUserIdAndDeviceType(userId, deviceType);
    }

    /**
     * 注销指定用户所指定的类型和id的设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void logout(@NonNull Object userId, @NonNull String deviceType, @Nullable String deviceId) {
        userDevicesDict.removeDeviceByUserIdAndDeviceTypeAndDeviceId(userId, deviceType, deviceId);
    }

    /**
     * access过期刷新接口。
     * <p>
     * 如果使用单token，则直接使用accessToken即可，在accessToken过期时再重新登录。
     * <p>
     * 使用双token时，accessToken过期时，可以利用refreshToken在此接口中刷新获得一个新的accessToken。
     *
     * @param refreshToken 与accessToken一起授予的refreshToken
     * @return 刷新成功（true）/ 失败（false）返回 [空] 则登录失败
     */
    @Nullable
    public static TokenPair refreshToken(@NonNull String refreshToken) {
        return auDefender.refreshToken(refreshToken);
    }

    /**
     * 查询所有用户信息，一个map userId->设备信息列表
     *
     * @return 一个map userId->设备信息列表
     */
    @NonNull
    public static Map<Object, List<Device>> queryAllUsersDevices() {
        HashMap<Object, List<Device>> map = new HashMap<>();
        AuHelper.queryAllUserId().forEach(userId -> map.put(userId, AuHelper.queryAllDeviceByUserId(userId)));
        return map;
    }

    /**
     * 获得指定设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @Nullable
    public static Device queryDeviceByUserIdAndDeviceTypeAndDeviceId(@NonNull Object userId, @NonNull String deviceType, @Nullable String deviceId) {
        return userDevicesDict.getDevice(userId, deviceType, deviceId);
    }

    /**
     * 当前访问用户的所有设备
     *
     * @return 所有设备列表
     */
    @NonNull
    public static List<Device> queryAllDeviceFromCurrentUser() {
        return userDevicesDict.listDevicesForCurrentUser();
    }

    /**
     * @return 所有当前有效登录用户的用户id, 当开启redis缓存时，userId返回为String数组
     */
    @NonNull
    public static List<Object> queryAllUserId() {
        return userDevicesDict.listUserId();
    }

    /**
     * 获得指定userId的所有设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @NonNull
    public static List<Device> queryAllDeviceByUserId(@NonNull Object userId) {
        return userDevicesDict.listDevicesByUserId(userId);
    }

    /**
     * 获得指定userId的所有设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @NonNull
    public static List<Device> queryAllDeviceByUserIdAndDeviceType(@NonNull Object userId, @NonNull String deviceType) {
        return userDevicesDict.listDevicesByUserId(userId).stream()
                .filter(device -> device.getType().equals(deviceType))
                .collect(Collectors.toList());
    }

    // ************************************     【在线/活跃】      ************************************ //

    /**
     * 判断某个用户是否有设备【在线/活跃】（默认60秒内），
     *
     * @param userId 用户id
     * @return 用户是否在线
     */
    public static boolean checkUserIsActive(@NonNull Object userId) {
        return checkUserIsActive(userId, 60000L);
    }

    /**
     * 判断某个用户是否【在线/活跃】
     *
     * @param userId 用户id
     * @param time   时间间隔
     * @return 用户是否在线
     */
    public static boolean checkUserIsActive(@NonNull Object userId, @NonNull String time) {
        return userDevicesDict.listActiveUserDevices(userId, TimeUtils.parseTimeValue(time)).size() > 0;
    }

    /**
     * 判断某个用户是否【在线/活跃】
     *
     * @param userId 用户id
     * @param ms     时间间隔(ms)
     * @return 用户是否在线
     */
    public static boolean checkUserIsActive(@NonNull Object userId, long ms) {
        return userDevicesDict.listActiveUserDevices(userId, ms).size() > 0;
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户数量
     *
     * @return 用户id数组
     */
    public static int queryNumberOfActiveUsers() {
        return userDevicesDict.listActiveUsers(60000L).size();
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    public static int queryNumberOfActiveUsers(@NonNull String time) {
        return userDevicesDict.listActiveUsers(TimeUtils.parseTimeValue(time)).size();
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param ms 时间间隔(ms)
     * @return 用户id数组
     */
    public static int queryNumberOfActiveUsers(long ms) {
        return userDevicesDict.listActiveUsers(ms).size();
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户Id数组
     *
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> queryActiveUsers() {
        return userDevicesDict.listActiveUsers(60000L);
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> queryActiveUsers(@NonNull String time) {
        return userDevicesDict.listActiveUsers(TimeUtils.parseTimeValue(time));
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param ms 时间间隔(ms)
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> queryActiveUsers(long ms) {
        return userDevicesDict.listActiveUsers(ms);
    }

    // **************************************     ip黑名单      ************************************** //

    /**
     * 获得只可观察的黑名单请求元信息
     *
     * @return 不可修改的黑名单请求元信息
     */
    @NonNull
    public static Collection<RequestMeta> queryMetaOfIpBlacklist() {
        return Collections.unmodifiableCollection(httpd.getIpBlacklist());
    }

    /**
     * 获得只可观察的黑名单请求元信息
     *
     * @return 不可修改的黑名单请求元信息
     */
    @NonNull
    public static List<String> queryIpBlacklist() {
        return httpd.getIpBlacklist().stream().map(RequestMeta::getIp).collect(Collectors.toList());
    }

    // *************************************     api权限、rate-limit 自定义      ************************************* //

    // 1、配置api的 param权限
    // 2、path权限
    // 3、配置数据权限
    // 4、rate速率配置

    /**
     * 可使用{@link org.springframework.web.bind.annotation.RequestBody}获得，或者{@code new PermRolesMeta.Vo()}
     * <p>
     * <p>
     * 必须要的三个字段：{@code operate, method, api}
     * <p>
     * operate 支持四种操作: ADD, DELETE, MODIFY, GET （可小写）
     * <p>
     * example ：
     * <pre>
     * {
     *     "operate": "modify",
     *     "method": "get",
     *     "api": "/api/test/role-ada",
     *     "requireRoles": ["admin","zxc"],
     *     "excludeRoles": ["small-black,dog", cat","apple"],
     *     "requirePermissions": ["cur"]
     * }
     * </pre>
     * <p>
     * 缺失为不修改
     *
     * @param permRolesMetaVo permRolesMetaVo
     * @return 操作之后的结果
     */
    public static PermRolesMeta operatePermRolesMeta(PermRolesMeta.Vo permRolesMetaVo) {
        return permissionDict.modify(permRolesMetaVo);
    }

    // **************************************     RSA      ************************************** //

    /**
     * @return RSA 公钥
     */
    @NonNull
    public static String getRSAPublicKey() {
        return AuKey.getPublicKeyString();
    }

    /**
     * @return RSA 私钥
     */
    @NonNull
    public static String getRSAPrivateKey() {
        return AuKey.getPrivateKeyString();
    }

    /**
     * 打开自动刷新RSA，会将自定义的RSA关闭
     */
    public static void openAutoRefresh() {
        AuKey.setAuto(true);
    }

    /**
     * 关闭自动刷新RSA，需要额外指定公钥私钥对
     */
    public static void closeAutoRefreshAndSetup(String publicKey, String privateKey) {
        AuKey.setAuKeyPair(publicKey, privateKey);
    }

    // **************************************     缓存      ************************************** //

    /**
     * 重新加载所有缓存
     */
    public static void reloadCache() {
        cache.reload();
    }

    private AuHelper() {
    }
}
