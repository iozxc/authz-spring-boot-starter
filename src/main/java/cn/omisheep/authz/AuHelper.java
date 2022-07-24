package cn.omisheep.authz;

/*
                 _    _
    /\          | |  | |
   /  \   _   _ | |_ | |__   ____
  / /\ \ | | | || __|| '_ \ |_  /
 / ____ \| |_| || |_ | | | | / /
/_/    \_\\__,_| \__||_| |_|/___|
 */

import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.ThreadWebEnvironmentException;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.codec.AuthzRSAManager;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.AuthzManager.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuHelper {

    // **************************************     登录 & 用户设备      ************************************** //

    /**
     * @param userId 用户id - 不为null
     * @return 授权后的tokenPair(accessToken以及refreshToken)，返回空则登录失败
     */
    @Nullable
    public static TokenPair login(@NonNull Object userId) {
        String deviceType;
        try {
            deviceType = getHttpMeta().getUserAgent();
        } catch (ThreadWebEnvironmentException e) {
            deviceType = "unknown";
        }
        return login(userId, deviceType, null);
    }

    /**
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null 默认为unknown
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
        return AuthzDefender.grant(userId, deviceType, deviceId);
    }

    /**
     * 注销当前用户当前设备
     */
    public static void logout() {
        AuthzDefender.logout();
    }

    /**
     * 注销当前用户所有设备
     */
    public static void logoutAll() {
        AuthzDefender.logoutAll();
    }

    /**
     * 注销当前用户所指定的类型的所有设备
     *
     * @param deviceType 指定设备类型
     */
    public static void logout(@NonNull String deviceType) {
        AuthzDefender.logout(deviceType);
    }

    /**
     * 注销当前用户所指定的类型和id的设备
     *
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void logout(@NonNull String deviceType, @Nullable String deviceId) {
        AuthzDefender.logout(deviceType, deviceId);
    }

    /**
     * 注销指定用户所有设备，建议用于管理员，如果某用户想通过自己id注销自己，建议加上参数权限判断
     *
     * @param userId 用户id
     */
    public static void logoutAll(@NonNull Object userId) {
        AuthzDefender.logoutAll(userId);
    }

    /**
     * 注销指定用户所指定的类型的所有设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     */
    public static void logout(@NonNull Object userId, @NonNull String deviceType) {
        AuthzDefender.logout(userId, deviceType);
    }

    /**
     * 注销指定用户所指定的类型和id的设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void logout(@NonNull Object userId, @NonNull String deviceType, @Nullable String deviceId) {
        AuthzDefender.logout(userId, deviceType, deviceId);
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
        return AuthzDefender.refreshToken(refreshToken);
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
        return userDevicesDict.listDevicesByUserId(userId).stream().filter(device -> device.getType().equals(deviceType)).collect(Collectors.toList());
    }

    // **************************************     状态管理      ************************************** //

    /**
     * @return 当前请求是否登录 true为登录、false为未登录
     */
    public static boolean isLogin() {
        return AuthzDefender.isLogin();
    }

    /**
     * 若当前线程未绑定HttpRequest。则抛出 {@link ThreadWebEnvironmentException}
     *
     * @return 获得当前请求的HttpMeta信息
     * @throws ThreadWebEnvironmentException 线程Web环境异常
     */
    public static HttpMeta getHttpMeta() throws ThreadWebEnvironmentException {
        return AUtils.getCurrentHttpMeta();
    }

    /**
     * @return 获得当前请求的Token信息
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static Token getToken() throws NotLoginException {
        return AUtils.getCurrentToken();
    }

    /**
     * @return 获得当前请求的userId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static Object getUserId() throws NotLoginException {
        return AUtils.getCurrentToken().getUserId();
    }

    /**
     * @return 获得当前请求的deviceType
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static String getDeviceType() throws NotLoginException {
        return AUtils.getCurrentToken().getDeviceType();
    }

    /**
     * @return 获得当前请求的deviceId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static String getDeviceId() throws NotLoginException {
        return AUtils.getCurrentToken().getDeviceId();
    }

    /**
     * @param role 所指定的角色
     * @return 判断当前请求用户是否有指定角色
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static boolean hasRole(String role) throws NotLoginException {
        return AuthzDefender.hasRoles(Collections.singletonList(role));
    }

    /**
     * @param roles 所指定的角色
     * @return 判断当前请求用户是否有指定角色
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static boolean hasRoles(List<String> roles) throws NotLoginException {
        return AuthzDefender.hasRoles(roles);
    }

    /**
     * @param permission 所指定的权限
     * @return 判断当前请求用户是否有指定角色
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static boolean hasPermission(String permission) throws NotLoginException {
        return AuthzDefender.hasPermissions(Collections.singletonList(permission));
    }

    /**
     * @param permissions 所指定的权限
     * @return 判断当前请求用户是否有指定角色
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static boolean hasPermissions(List<String> permissions) throws NotLoginException {
        return AuthzDefender.hasPermissions(permissions);
    }

    // ************************************     【在线/活跃】      ************************************ //

    /**
     * 判断某个用户是否有设备【在线/活跃】（默认60秒内）
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

    // **************************************     黑名单操作      ************************************** //


    /**
     * 封禁 ip time时间
     *
     * @param ip   封禁的ip
     * @param time 时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyIP(@NonNull String ip, @NonNull String time) {
        Blacklist.IP.add(ip, time);
    }

    /**
     * 封禁 ip time时间
     *
     * @param ip 封禁的ip
     * @param ms 毫秒
     */
    public static void denyIP(@NonNull String ip, @NonNull long ms) {
        denyIP(ip, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 ipRange网段 time时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param time    时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyIPRange(@NonNull String ipRange, @NonNull String time) {
        Blacklist.IPRangeDeny.add(ipRange, time);
    }

    /**
     * 封禁 ipRange网段 time时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param ms      毫秒
     */
    public static void denyIPRange(@NonNull String ipRange, @NonNull long ms) {
        denyIPRange(ipRange, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId 封禁的userId
     * @param time   时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyUser(@NonNull Object userId, @NonNull String time) {
        Blacklist.User.add(userId, null, null, time);
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId 封禁的userId
     * @param ms     毫秒
     */
    public static void denyUser(@NonNull Object userId, @NonNull long ms) {
        denyUser(userId, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param time       时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String time) {
        Blacklist.User.add(userId, deviceType, null, time);
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param ms         毫秒
     */
    public static void denyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull long ms) {
        denyUser(userId, deviceType, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param deviceId   封禁的设备id
     * @param time       时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String deviceId, @NonNull String time) {
        Blacklist.User.add(userId, deviceType, deviceId, time);
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param deviceId   封禁的设备id
     * @param ms         毫秒
     */
    public static void denyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String deviceId, @NonNull long ms) {
        denyUser(userId, deviceType, deviceId, TimeUtils.parseTime(ms));
    }

    /**
     * @return 得到封禁的ip信息
     */
    @NonNull
    public static List<Blacklist.IP> getDenyIPInfo() {
        return Blacklist.IP.list();
    }

    /**
     * @return 得到封禁的iprange信息
     */
    @NonNull
    public static List<Blacklist.IPRangeDeny> getDenyIPRangeInfo() {
        return Blacklist.IPRangeDeny.list();
    }

    /**
     * @return 获得封禁用户的信息
     */
    @NonNull
    public static List<Blacklist.User> getDenyUserInfo() {
        return Blacklist.User.list();
    }

    /**
     * @param userId 指定用户id
     * @return 获得指定的封禁用户的信息
     */
    @NonNull
    public static List<Blacklist.User> getDenyUserInfo(@NonNull Object userId) {
        return Blacklist.User.list(userId);
    }

    /**
     * @param userId     指定用户id
     * @param deviceType 指定设备deviceType
     * @param deviceId   指定设备deviceId
     * @return 封禁信息
     */
    @Nullable
    public static Blacklist.User getDenyUserInfo(@NonNull Object userId, @Nullable String deviceType, @Nullable String deviceId) {
        return Blacklist.User.get(userId, deviceType, deviceId);
    }

    /**
     * 修改 ip的封禁时间时间
     *
     * @param ip   封禁的ip
     * @param time 时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyIP(@NonNull String ip, @NonNull String time) {
        Blacklist.IP.change(ip, time);
    }

    /**
     * 修改 ip的封禁时间时间
     *
     * @param ip 封禁的ip
     * @param ms 毫秒
     */
    public static void changeDenyIP(@NonNull String ip, @NonNull long ms) {
        changeDenyIP(ip, TimeUtils.parseTime(ms));
    }

    /**
     * 修改 ipRange网段封禁的时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param time    时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyIPRange(@NonNull String ipRange, @NonNull String time) {
        Blacklist.IPRangeDeny.change(ipRange, time);
    }

    /**
     * 修改 ipRange网段封禁的时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param ms      毫秒
     */
    public static void changeDenyIPRange(@NonNull String ipRange, @NonNull long ms) {
        changeDenyIPRange(ipRange, TimeUtils.parseTime(ms));
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId 封禁的userId
     * @param time   时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyUser(@NonNull Object userId, @NonNull String time) {
        Blacklist.User.change(userId, null, null, time);
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId 封禁的userId
     * @param ms     毫秒
     */
    public static void changeDenyUser(@NonNull Object userId, @NonNull long ms) {
        changeDenyUser(userId, TimeUtils.parseTime(ms));
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param time       时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String time) {
        Blacklist.User.change(userId, deviceType, null, time);
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param ms         毫秒
     */
    public static void changeDenyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull long ms) {
        changeDenyUser(userId, deviceType, TimeUtils.parseTime(ms));
    }


    /**
     * 修改 userId封禁时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param deviceId   封禁的设备id
     * @param time       时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String deviceId, @NonNull String time) {
        Blacklist.User.change(userId, deviceType, deviceId, time);
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param deviceId   封禁的设备id
     * @param ms         毫秒
     */
    public static void changeDenyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String deviceId, @NonNull long ms) {
        changeDenyUser(userId, deviceType, deviceId, TimeUtils.parseTime(ms));
    }

    /**
     * 移除封禁
     *
     * @param ip ip
     */
    public static void removeDenyIP(@NonNull String ip) {
        Blacklist.IP.remove(ip);
    }

    /**
     * 移除封禁
     *
     * @param ipRange ip范围
     */
    public static void removeDenyIPRange(@NonNull String ipRange) {
        Blacklist.IPRangeDeny.remove(ipRange);
    }


    /**
     * 移除封禁
     *
     * @param userId 指定用户
     */
    public static void removeDenyUser(@NonNull Object userId) {
        Blacklist.User.remove(userId, null, null);
    }

    /**
     * 移除封禁
     *
     * @param userId     指定用户
     * @param deviceType 指定设备类型
     */
    public static void removeDenyUser(@NonNull Object userId, @NonNull String deviceType) {
        Blacklist.User.remove(userId, deviceType, null);
    }

    /**
     * 移除封禁
     *
     * @param userId     指定用户
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void removeDenyUser(@NonNull Object userId, @NonNull String deviceType, @NonNull String deviceId) {
        Blacklist.User.remove(userId, deviceType, deviceId);
    }

    // **************************************     RSA      ************************************** //

    /**
     * @return RSA 公钥
     */
    @NonNull
    public static String getRSAPublicKey() {
        return AuthzRSAManager.getPublicKeyString();
    }

    /**
     * @return RSA 私钥
     */
    @NonNull
    public static String getRSAPrivateKey() {
        return AuthzRSAManager.getPrivateKeyString();
    }

    public static String encrypt(String plaintext) {
        return AuthzRSAManager.encrypt(plaintext);
    }

    public static String decrypt(String encryptText) {
        return AuthzRSAManager.decrypt(encryptText);
    }

    /**
     * 打开自动刷新RSA，会将自定义的RSA关闭
     */
    public static void openAutoRefresh() {
        AuthzRSAManager.setAuto(true);
    }

    /**
     * 关闭自动刷新RSA，需要额外指定公钥私钥对
     */
    public static void closeAutoRefreshAndSetup(String publicKey, String privateKey) {
        AuthzRSAManager.setAuKeyPair(publicKey, privateKey);
    }

    // **************************************     缓存      ************************************** //

    /**
     * 重新加载所有缓存
     */
    public static void reloadCache() {
        cache.reload();
    }

    /**
     * 重新加载所有缓存
     */
    public static void reloadCache(String... keys) {
        cache.reload(keys);
    }

    /**
     * 重新加载指定的缓存
     */
    @SafeVarargs
    public static void reloadCache(Collection<String>... keys) {
        cache.reload(keys);
    }

    // *************************************     api权限、数据权限、rate-limit 动态修改      ************************************* //

    /**
     * 动态修改api权限和api的参数权限
     * 更多操作看Dashboard
     * 可使用{@link org.springframework.web.bind.annotation.RequestBody}获得，或者{@code new AuthzModifier();}
     * <p>
     * <p>
     * 共的13个字段：{@code 1.operate 2.target 3.method, 4.api 5.value 6.index 7.range 8.resources 9.className 10.condition 11.argsMap 12.role 13.permission }
     * <p>
     * operate 支持四种操作:
     * <li>ADD</li>
     * <li>DELETE(DEL)</li>
     * <li>MODIFY(UPDATE)</li>
     * <li>GET(READ)</li>
     * <br>
     * target 有3种类型 api，路径参数，请求参数 <br>
     * 其中值一共有5钟:
     * <li>API</li>
     * <li>PATH_VARIABLE_ROLE(PATH_VARIABLE_ROLE)</li>
     * <li>PATH_VARIABLE_PERMISSION(PATH_VAR_PERMISSION)</li>
     * <li>REQUEST_PARAM_ROLE(PARAM_ROLE)</li>
     * <li>REQUEST_PARAM_PERMISSION(PARAM_PERMISSION)</li>
     * <p>
     * example 对于api的相关操作:
     * <p>
     * 对于api的添加操作：
     * <pre>
     * {
     *     "operate": "add",
     *     "target": "api",
     *     "method": "get",
     *     "api": "/test/role-ada"
     *     "role": {
     *         "require": ["admin","zxc"],
     *         "exclude": ["small-black,dog", "cat","apple"]
     *     },
     *     "permission": {
     *         ...
     *     }
     * }
     * </pre>
     * 对于api的删除操作：
     * <pre>
     * {
     *     "operate": "del",
     *     "target": "api",
     *     "method": "get",
     *     "api": "/test/role-ada"
     * }
     * </pre>
     * 对于api的修改操作：(缺失为不修改)
     * <pre>
     * {
     *     "operate": "modify",
     *     "target": "api",
     *     "method": "get",
     *     "api": "/test/role-ada",
     *     "role": {
     *         "require": ["admin","zxc"],
     *         "exclude": ["small-black,dog", "cat","apple"]
     *     },
     *     "permission": {
     *         ...
     *     }
     * }
     * </pre>
     * 对于api的查看操作：
     * <pre>
     * {
     *     "operate": "get",
     *     "target": "api",
     *     "method": "get",
     *     "api": "/test/role-ada"
     * }
     * </pre>
     * <p>
     * example 对于参数的相关操作:
     * <p>
     * 对于参数的添加操作：
     * <pre>
     * 1、在/test/role-ada接口上参数名为id添加限制权限限制。
     * user用户使用参数id访问接口时值只能在1-100内，否则权限错误
     * {
     *     "operate": "add",
     *     "target": "request_param_role",
     *     "method": "get",
     *     "api": "/test/role-ada",
     *     "value": "id",
     *     "role": {
     *         "require":["user"]
     *     },
     *     "range": ["1-100"]
     * }
     * 2、在/test/role-ada接口上参数名为id添加限制权限限制。
     * 用户访问接口时如果id的值在1-200内，如果没有dog权限，将出现权限错误，被拦截
     * {
     *     "operate": "add",
     *     "target": "param_permission",
     *     "method": "get",
     *     "api": "/test/role-ada",
     *     "value": "id",
     *     "role: {
     *         "require":["dog"]
     *     },
     *     "resources": ["1-100"]
     * }
     * 3、在/test/role-ada/{name}接口上路径参数名为name添加限制权限限制。
     * 用户'小学生'只能访问路径为/test/role-ada/apple或者/test/role-ada/good-apple，如果为/test/role-ada/bad-apple将报错
     * {
     *     "operate": "add",
     *     "target": "path_variable_role",
     *     "method": "get",
     *     "api": "/test/role-ada/{name}",
     *     "value": "name",
     *     "role: {
     *         "require":["小学生"]
     *     },
     *     "range": ["apple","good-apple"]
     * }
     * </pre>
     * 对参数权限进行查看、修改、删除
     * <pre>
     * 1、删除/test/role-ada/{name}接口上路径参数名为name的限制。
     * 用户'小学生'能够自由访问任意/test/role-ada/apple或者/test/role-ada/good-apple或者/test/role-ada/bad-apple
     * {
     *     "operate": "del",
     *     "target": "path_variable_role",
     *     "method": "get",
     *     "api": "/test/role-ada/{name}",
     *     "value": "name"
     * }
     * 2、如果在某个接口上添加了很多个限制条件，可以先查看，然后确认自己想具体删除哪个或者修改哪个，再附带index来指定修改的参数权限
     * 查看
     * {
     *     "operate": "get",
     *     "target": "path_variable_role",
     *     "method": "get",
     *     "api": "/test/role-ada/{name}",
     *     "value": "name"
     * }
     * 3、删除第2个,index从0开始
     * {
     *     "operate": "del",
     *     "target": "path",
     *     "method": "get",
     *     "api": "/test/role-ada/{name}",
     *     "value": "name",
     *     "index": 1
     * }
     * 3、修改第2个,index从0开始
     * 让'小学生'可以查看坏苹果
     * {
     *     "operate": "modify",
     *     "target": "path_variable_role",
     *     "method": "get",
     *     "api": "/test/role-ada/{name}",
     *     "value": "name",
     *     "index": 1,
     *     "role: {
     *         "require":["小学生"]
     *     },
     *     "range": ["apple","bad-apple","good-apple"]
     * }
     * </pre>
     * <p>
     * <p>
     * <p>
     * 删除只能删除一整个，不能做到单独删除其中的requireRoles但是其他的保持不动，只能通过覆盖来操作
     *
     * @param authzModifier authzModifier
     * @return 操作之后的结果
     * {@link cn.omisheep.authz.core.auth.rpd.PermRolesMeta} \
     * {@link cn.omisheep.authz.core.auth.rpd.ParamMetadata} \
     * {@link cn.omisheep.authz.core.auth.rpd.PermRolesMeta.Meta}
     */
    @Nullable
    public static Object authzModify(@NonNull AuthzModifier authzModifier) {
        return modify(authzModifier);
    }

    public static class Callback {
        /**
         * 设置封禁和解封时的回调函数 「或者」 继承{@link RateLimitCallback} 将其注册入Spring容器中
         *
         * @param rateLimitCallback 封禁和解封时的回调函数
         */
        public static void setRateLimitCallback(RateLimitCallback rateLimitCallback) {
            Httpd.setRateLimitCallback(rateLimitCallback);
        }
    }

    private AuHelper() {
    }
}
