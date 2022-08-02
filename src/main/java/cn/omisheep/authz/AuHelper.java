package cn.omisheep.authz;

/*
                 _    _
    /\   v1.2   | |  | |
   /  \   _   _ | |_ | |__  _authz
  / /\ \ | | | || __|| '_ \ |_  /
 / ____ \| |_| || |_ | | | | / /
/_/    \_\\__,_| \__||_| |_|/___|
 */

import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.RefreshTokenExpiredException;
import cn.omisheep.authz.core.ThreadWebEnvironmentException;
import cn.omisheep.authz.core.auth.deviced.Device;
import cn.omisheep.authz.core.auth.deviced.DeviceCountInfo;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.callback.AuthorizationCallback;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.codec.AuthzRSAManager;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.helper.AuthzGranterHelper;
import cn.omisheep.authz.core.helper.AuthzStateHelper;
import cn.omisheep.authz.core.helper.BaseHelper;
import cn.omisheep.authz.core.helper.OpenAuthHelper;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.oauth.AuthorizationException;
import cn.omisheep.authz.core.oauth.AuthorizedDeviceDetails;
import cn.omisheep.authz.core.oauth.ClientDetails;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.tk.IssueToken;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.AuthzManager.modify;

/**
 * 时间字符串均采用如下格式 <br>
 * "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.2
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuHelper extends BaseHelper {

    // **************************************     登录 & 用户设备      ************************************** //

    /**
     * 用户登录 <br>
     *
     * @param userId 用户id - 不为null
     * @return 授权后的tokenPair(accessToken以及refreshToken)，返回空则登录失败
     */
    @Nullable
    public static IssueToken login(@NonNull Object userId) {
        return AuthzGranterHelper.grant(userId);
    }

    /**
     * 用户登录 <br>
     *
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null 默认为unknown
     * @return 授权后的tokenPair(accessToken以及refreshToken)，返回空则登录失败
     */
    @Nullable
    public static IssueToken login(@NonNull Object userId,
                                   @NonNull String deviceType) {
        return login(userId, deviceType, null);
    }

    /**
     * 用户登录 <br>
     *
     * @param userId     用户id - 不为null
     * @param deviceType 设备系统类型 - 不为null
     * @param deviceId   设备id - 可为null 且为 "" 时于 null等价
     * @return 授权后的tokenPair(accessToken以及refreshToken)，返回空则登录失败
     */
    @Nullable
    public static IssueToken login(@NonNull Object userId,
                                   @NonNull String deviceType,
                                   @Nullable String deviceId) {
        return AuthzGranterHelper.grant(userId, deviceType, deviceId);
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
    @NonNull
    public static IssueToken refreshToken(@NonNull String refreshToken) throws RefreshTokenExpiredException {
        return AuthzGranterHelper.refreshToken(refreshToken);
    }

    /**
     * 注销当前用户当前设备
     */
    public static void logout() {
        AuthzGranterHelper.logout();
    }

    /**
     * 注销当前用户所有设备
     */
    public static void logoutAll() {
        AuthzGranterHelper.logoutAll();
    }

    /**
     * 注销当前用户所指定的类型的所有设备
     *
     * @param deviceType 指定设备类型
     */
    public static void logout(@NonNull String deviceType) {
        AuthzGranterHelper.logout(deviceType);
    }

    /**
     * 注销当前用户所指定的类型和id的设备
     *
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void logout(@NonNull String deviceType,
                              @Nullable String deviceId) {
        AuthzGranterHelper.logout(deviceType, deviceId);
    }

    /**
     * 注销指定用户所有设备，建议用于管理员，如果某用户想通过自己id注销自己，建议加上参数权限判断
     *
     * @param userId 用户id
     */
    public static void logoutAll(@NonNull Object userId) {
        AuthzGranterHelper.logoutAll(userId);
    }

    /**
     * 注销指定用户所指定的类型的所有设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     */
    public static void logout(@NonNull Object userId,
                              @NonNull String deviceType) {
        AuthzGranterHelper.logout(userId, deviceType);
    }

    /**
     * 注销指定用户所指定的类型和id的设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void logout(@NonNull Object userId,
                              @NonNull String deviceType,
                              @Nullable String deviceId) {
        AuthzGranterHelper.logout(userId, deviceType, deviceId);
    }

    /**
     * 查询所有用户信息，一个map userId->设备信息列表
     *
     * @return 一个map userId->设备信息列表
     */
    @NonNull
    public static Map<Object, List<Device>> getAllUsersDevices() {
        HashMap<Object, List<Device>> map = new HashMap<>();
        AuHelper.getAllUserId().forEach(userId -> map.put(userId, AuHelper.getAllDeviceByUserId(userId)));
        return map;
    }

    /**
     * 获得指定设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @Nullable
    public static Device getDeviceByUserIdAndDeviceTypeAndDeviceId(@NonNull Object userId,
                                                                   @NonNull String deviceType,
                                                                   @Nullable String deviceId) {
        return userDevicesDict.getDevice(userId, deviceType, deviceId);
    }

    /**
     * 当前访问用户的所有设备
     *
     * @return 所有设备列表
     */
    @NonNull
    public static List<Device> getAllDeviceFromCurrentUser() throws NotLoginException {
        return userDevicesDict.listDevicesByUserId(getUserId());
    }

    /**
     * @return 所有当前有效登录用户的用户id, 当开启redis缓存时，userId返回为String数组
     */
    @NonNull
    public static List<Object> getAllUserId() {
        return userDevicesDict.listUserId();
    }

    /**
     * 获得指定userId的所有设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @NonNull
    public static List<Device> getAllDeviceByUserId(@NonNull Object userId) {
        return userDevicesDict.listDevicesByUserId(userId);
    }

    /**
     * 获得指定userId的所有设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @NonNull
    public static List<Device> getAllDeviceByUserIdAndDeviceType(@NonNull Object userId,
                                                                 @NonNull String deviceType) {
        return userDevicesDict.listDevicesByUserId(userId).stream().filter(
                device -> device.getDeviceType().equals(deviceType)).collect(Collectors.toList());
    }

    @NonNull
    public static List<AuthorizedDeviceDetails> getAllAuthorizationInfo() throws NotLoginException {
        return getAllAuthorizationInfo(getUserId());
    }


    @NonNull
    public static List<AuthorizedDeviceDetails> getAllAuthorizationInfo(Object userId) {
        return OpenAuthHelper.getAllAuthorizedDeviceDetails(userId);
    }

    // **************************************     状态&权限      ************************************** //

    /**
     * @return 当前请求是否登录 true为登录、false为未登录
     */
    public static boolean isLogin() {
        return AuthzStateHelper.isLogin();
    }

    /**
     * 若当前线程未绑定HttpRequest。则抛出 {@link ThreadWebEnvironmentException}
     *
     * @return 获得当前请求的HttpMeta信息
     * @throws ThreadWebEnvironmentException 线程Web环境异常
     */
    @NonNull
    public static HttpMeta getHttpMeta() throws ThreadWebEnvironmentException {
        return AUtils.getCurrentHttpMeta();
    }

    /**
     * @return 获得当前请求的Token信息
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @NonNull
    public static AccessToken getToken() throws NotLoginException {
        return AUtils.getCurrentToken();
    }

    /**
     * @return 获得当前请求的userId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static Object getUserId() throws NotLoginException {
        return AUtils.getCurrentToken().getUserId();
    }

    /**
     * @return 获得当前请求的deviceType
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static String getDeviceType() throws NotLoginException {
        return AUtils.getCurrentToken().getDeviceType();
    }

    /**
     * @return 获得当前请求的deviceId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static String getDeviceId() throws NotLoginException {
        return AUtils.getCurrentToken().getDeviceId();
    }

    /**
     * @return 获得当前请求的clientId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static String getClientId() throws NotLoginException {
        return AUtils.getCurrentToken().getClientId();
    }

    /**
     * @param role 所指定的角色
     * @return 判断当前请求用户是否有指定角色 若未登录返回false
     */
    public static boolean hasRole(String... role) {
        return hasRoles(Arrays.asList(role));
    }

    /**
     * @param roles 所指定的角色
     * @return 判断当前请求用户是否有指定角色 若未登录返回false
     */
    public static boolean hasRoles(List<String> roles) {
        return AuthzStateHelper.hasRoles(roles);
    }

    /**
     * @param permission 所指定的权限
     * @return 判断当前请求用户是否有指定角色 若未登录返回false
     */
    public static boolean hasPermission(String... permission) {
        return hasPermissions(Arrays.asList(permission));
    }

    /**
     * @param permissions 所指定的权限
     * @return 判断当前请求用户是否有指定角色
     */
    public static boolean hasPermissions(List<String> permissions) {
        return AuthzStateHelper.hasPermissions(permissions);
    }

    /**
     * @param scope 所指定的访问范围
     * @return 判断当前请求用户（oauth）是否有指定的访问权限
     */
    public static boolean hasScope(String... scope) {
        return AuthzStateHelper.hasScope(Arrays.asList(scope));
    }

    /**
     * @param scope 所指定的访问范围
     * @return 判断当前请求用户（oauth）是否有指定的访问权限
     */
    public static boolean hasScope(List<String> scope) {
        return AuthzStateHelper.hasScope(scope);
    }

    /**
     * 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1），超出会挤出最长时间未访问的设备。
     * count >= 1 or count = -1
     *
     * @param userId 用户id
     * @param types  deviceType
     * @param total  数量
     */
    public static void addDeviceTypesTotalLimit(Collection<String> types,
                                                int total) throws NotLoginException {
        addDeviceTypesTotalLimit(getUserId(), types, total);
    }

    /**
     * 获得一个可修改的 DeviceTypesTotalLimit list
     * count >= 1 or count = -1
     *
     * @param userId 用户id
     */
    public static List<DeviceCountInfo> getOrUpdateDeviceTypesTotalLimit(Object userId) {
        return userDevicesDict.getOrUpdateDeviceTypesTotalLimit(userId);
    }

    /**
     * 登录设备总数默不做限制【total为-1不做限制，最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param count 数量
     */
    public static void changeMaximumDeviceTotal(int count) throws NotLoginException {
        changeMaximumDeviceTotal(getUserId(), count);
    }

    /**
     * 同类型设备最多登录数 默认 1个【count最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param userId 用户id
     * @param count  数量
     */
    public static void changeMaximumSameTypeDeviceCount(int count) throws NotLoginException {
        changeMaximumSameTypeDeviceCount(getUserId(), count);
    }

    /**
     * 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1），超出会挤出最长时间未访问的设备。
     * count >= 1 or count = -1
     *
     * @param userId 用户id
     * @param types  deviceType
     * @param total  数量
     */
    public static void addDeviceTypesTotalLimit(Object userId,
                                                Collection<String> types,
                                                int total) {
        userDevicesDict.addDeviceTypesTotalLimit(userId, types, total);
    }

    /**
     * 同类型设备最多登录数 默认 1个【count最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param userId 用户id
     * @param count  数量
     */
    public static void changeMaximumSameTypeDeviceCount(Object userId,
                                                        int count) {
        userDevicesDict.changeMaximumSameTypeDeviceCount(userId, count);
    }

    /**
     * 登录设备总数默不做限制【total为-1不做限制，最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param userId 用户id
     * @param count  数量
     */
    public static void changeMaximumDeviceTotal(Object userId,
                                                int count) {
        userDevicesDict.changeMaximumDeviceTotal(userId, count);
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
    public static boolean checkUserIsActive(@NonNull Object userId,
                                            @NonNull String time) {
        return userDevicesDict.listActiveUserDevices(userId, TimeUtils.parseTimeValue(time)).size() > 0;
    }

    /**
     * 判断某个用户是否【在线/活跃】
     *
     * @param userId 用户id
     * @param ms     时间间隔(ms)
     * @return 用户是否在线
     */
    public static boolean checkUserIsActive(@NonNull Object userId,
                                            long ms) {
        return userDevicesDict.listActiveUserDevices(userId, ms).size() > 0;
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户数量
     *
     * @return 用户id数组
     */
    public static int getNumberOfActiveUsers() {
        return userDevicesDict.listActiveUsers(60000L).size();
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    public static int getNumberOfActiveUsers(@NonNull String time) {
        return userDevicesDict.listActiveUsers(TimeUtils.parseTimeValue(time)).size();
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param ms 时间间隔(ms)
     * @return 用户id数组
     */
    public static int getNumberOfActiveUsers(long ms) {
        return userDevicesDict.listActiveUsers(ms).size();
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户Id数组
     *
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> getActiveUsers() {
        return userDevicesDict.listActiveUsers(60000L);
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> getActiveUsers(@NonNull String time) {
        return userDevicesDict.listActiveUsers(TimeUtils.parseTimeValue(time));
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param ms 时间间隔(ms)
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> getActiveUsers(long ms) {
        return userDevicesDict.listActiveUsers(ms);
    }

    // **************************************     黑名单操作      ************************************** //

    /**
     * 封禁 ip time时间
     *
     * @param ip   封禁的ip
     * @param time 时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyIP(@NonNull String ip,
                              @NonNull String time) {
        Blacklist.IP.add(ip, time);
    }

    /**
     * 封禁 ip time时间
     *
     * @param ip 封禁的ip
     * @param ms 毫秒
     */
    public static void denyIP(@NonNull String ip,
                              @NonNull long ms) {
        denyIP(ip, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 ipRange网段 time时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param time    时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyIPRange(@NonNull String ipRange,
                                   @NonNull String time) {
        Blacklist.IPRangeDeny.add(ipRange, time);
    }

    /**
     * 封禁 ipRange网段 time时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param ms      毫秒
     */
    public static void denyIPRange(@NonNull String ipRange,
                                   @NonNull long ms) {
        denyIPRange(ipRange, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId 封禁的userId
     * @param time   时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyUser(@NonNull Object userId,
                                @NonNull String time) {
        Blacklist.User.add(userId, null, null, time);
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId 封禁的userId
     * @param ms     毫秒
     */
    public static void denyUser(@NonNull Object userId,
                                @NonNull long ms) {
        denyUser(userId, TimeUtils.parseTime(ms));
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param time       时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void denyUser(@NonNull Object userId,
                                @NonNull String deviceType,
                                @NonNull String time) {
        Blacklist.User.add(userId, deviceType, null, time);
    }

    /**
     * 封禁 userId time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param ms         毫秒
     */
    public static void denyUser(@NonNull Object userId,
                                @NonNull String deviceType,
                                @NonNull long ms) {
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
    public static void denyUser(@NonNull Object userId,
                                @NonNull String deviceType,
                                @NonNull String deviceId,
                                @NonNull String time) {
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
    public static void denyUser(@NonNull Object userId,
                                @NonNull String deviceType,
                                @NonNull String deviceId,
                                @NonNull long ms) {
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
    public static Blacklist.User getDenyUserInfo(@NonNull Object userId,
                                                 @Nullable String deviceType,
                                                 @Nullable String deviceId) {
        return Blacklist.User.get(userId, deviceType, deviceId);
    }

    /**
     * 修改 ip的封禁时间时间
     *
     * @param ip   封禁的ip
     * @param time 时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyIP(@NonNull String ip,
                                    @NonNull String time) {
        Blacklist.IP.change(ip, time);
    }

    /**
     * 修改 ip的封禁时间时间
     *
     * @param ip 封禁的ip
     * @param ms 毫秒
     */
    public static void changeDenyIP(@NonNull String ip,
                                    @NonNull long ms) {
        changeDenyIP(ip, TimeUtils.parseTime(ms));
    }

    /**
     * 修改 ipRange网段封禁的时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param time    时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyIPRange(@NonNull String ipRange,
                                         @NonNull String time) {
        Blacklist.IPRangeDeny.change(ipRange, time);
    }

    /**
     * 修改 ipRange网段封禁的时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param ms      毫秒
     */
    public static void changeDenyIPRange(@NonNull String ipRange,
                                         @NonNull long ms) {
        changeDenyIPRange(ipRange, TimeUtils.parseTime(ms));
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId 封禁的userId
     * @param time   时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyUser(@NonNull Object userId,
                                      @NonNull String time) {
        Blacklist.User.change(userId, null, null, time);
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId 封禁的userId
     * @param ms     毫秒
     */
    public static void changeDenyUser(@NonNull Object userId,
                                      @NonNull long ms) {
        changeDenyUser(userId, TimeUtils.parseTime(ms));
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param time       时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
     */
    public static void changeDenyUser(@NonNull Object userId,
                                      @NonNull String deviceType,
                                      @NonNull String time) {
        Blacklist.User.change(userId, deviceType, null, time);
    }

    /**
     * 修改 userId封禁时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param ms         毫秒
     */
    public static void changeDenyUser(@NonNull Object userId,
                                      @NonNull String deviceType,
                                      @NonNull long ms) {
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
    public static void changeDenyUser(@NonNull Object userId,
                                      @NonNull String deviceType,
                                      @NonNull String deviceId,
                                      @NonNull String time) {
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
    public static void changeDenyUser(@NonNull Object userId,
                                      @NonNull String deviceType,
                                      @NonNull String deviceId,
                                      @NonNull long ms) {
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
    public static void removeDenyUser(@NonNull Object userId,
                                      @NonNull String deviceType) {
        Blacklist.User.remove(userId, deviceType, null);
    }

    /**
     * 移除封禁
     *
     * @param userId     指定用户
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     */
    public static void removeDenyUser(@NonNull Object userId,
                                      @NonNull String deviceType,
                                      @NonNull String deviceId) {
        Blacklist.User.remove(userId, deviceType, deviceId);
    }

    /**
     * 主动修改 数据库、redis时，调用此方法
     *
     * @param clientid 客户端id
     */
    public static void reloadClient(String clientid) {
        cache.delSneaky(Constants.CLINT_PREFIX.get() + clientid);
        openAuthLibrary.getClientById(clientid);
    }

    /**
     * 主动修改 数据库、redis时，调用此方法
     *
     * @param userId 用户id
     */
    public static void reloadRoles(Object userId) {
        cache.delSneaky(Constants.ROLES_BY_USER_KEY_PREFIX.get() + userId);
        permLibrary.getRolesByUserId(userId);
    }

    /**
     * 主动修改 数据库、redis时，调用此方法
     *
     * @param role role
     */
    public static void reloadPermissions(String role) {
        cache.delSneaky(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX.get() + role);
        permLibrary.getPermissionsByRole(role);
    }

    // **************************************     OpenAuth 2.0      ************************************** //

    /**
     * <li>1.注册客户端 {@link #clientRegister(String, String)} -> 返回客户端信息（客户端id，客户端name，客户端密钥，重定向url）</li>
     * <li>2.获取授权码 {@link #createAuthorizationCode(String, String, String)} -> 客户端id+登录用户+权限范围 、获得登录用户的授权码</li>
     * <li>3.验证授权码 {@link #authorize(String, String, String)}-> 利用授权码去获得TokenPair</li>
     *
     * @since 1.2.0
     */
    public static class OpenAuth {

        /**
         * 授权码登录 （授权类型 authorization_code）- 不需要登录 <br>
         * <p>
         * 验证授权码是否有效，成功返回TokenPair
         *
         * @param clientId          客户端id
         * @param clientSecret      客户端密钥
         * @param authorizationCode 授权码
         * @return 授权后的tokenPair(accessToken以及refreshToken)
         * @throws AuthorizationException 验证失败，客户端密码错误 或者 授权码失效(过期 或者 已使用)
         */
        @Nullable
        public static IssueToken authorizeByCode(@NonNull String clientId,
                                                 @NonNull String clientSecret,
                                                 @NonNull String authorizationCode) throws AuthorizationException {
            return OpenAuthHelper.authorizeByCode(clientId, clientSecret, authorizationCode);
        }

        /**
         * 登录授权（授权类型 password） - 需要提前验证账号密码 <br>
         *
         * @param clientId     客户端id
         * @param clientSecret 客户端密钥
         * @param scope        授权范围
         * @param userId       userId
         * @return 授权后的tokenPair(accessToken以及refreshToken)
         * @throws AuthorizationException 验证失败，客户端密码错误 或 未登录
         */
        @Nullable
        public static IssueToken authorizeByPasswrod(@NonNull String clientId,
                                                     @NonNull String clientSecret,
                                                     @NonNull String scope,
                                                     @NonNull Object userId) throws AuthorizationException {
            return OpenAuthHelper.authorizeByPassword(clientId, clientSecret, scope, userId);
        }

        /**
         * 登录授权（授权类型 password） - 需要登录 <br>
         *
         * @param clientId     客户端id
         * @param clientSecret 客户端密钥
         * @param scope        授权范围
         * @return 授权后的tokenPair(accessToken以及refreshToken)
         * @throws AuthorizationException 验证失败，客户端密码错误 或 未登录
         */
        @Nullable
        public static IssueToken authorizeByPasswrod(@NonNull String clientId,
                                                     @NonNull String clientSecret,
                                                     @NonNull String scope) throws AuthorizationException {
            return OpenAuthHelper.authorizeByPassword(clientId, clientSecret, scope, getUserId());
        }

        /**
         * 客户端登录 （授权类型 client_credentials）- 不需要登录 <br>
         * <p>
         * 成功返回TokenPair
         *
         * @param clientId     客户端id
         * @param clientSecret 客户端密钥
         * @param scope        授权范围
         * @return 授权后的tokenPair(accessToken以及refreshToken)
         * @throws AuthorizationException 客户端密码错误
         */
        @Nullable
        public static IssueToken authorizeByClient(@NonNull String clientId,
                                                   @NonNull String clientSecret,
                                                   @NonNull String scope) throws AuthorizationException {
            return OpenAuthHelper.authorizeByClient(clientId, clientSecret, scope);
        }

        /**
         * 若未登录，抛出 {@link  AuthorizationException } 授权失败
         * 指定(客户端, 授权范围) -> 获得登录用户的授权码
         * 获取授权码 <br>
         * 若redirectUrl与所注册客户端的redirectUrl不一致，抛出异常
         *
         * @param clientId    客户端id
         * @param scope       授予的权限范围
         * @param redirectUrl 重定向url
         * @return Authorization Code 授权码
         * @throws AuthorizationException 授权失败
         */
        @NonNull
        public static String createAuthorizationCode(@NonNull String clientId,
                                                     @NonNull String scope,
                                                     @NonNull String redirectUrl) throws AuthorizationException {
            if (isLogin() && agreeAuthorize(clientId)) {
                return OpenAuthHelper.createAuthorizationCode(clientId, scope, redirectUrl, getUserId());
            }
            throw AuthorizationException.privilegeGrantFailed();
        }

        /**
         * 若未登录，抛出 {@link  AuthorizationException } 授权失败
         * 指定(客户端, 授权范围-默认权限) -> 获得登录用户的授权码
         * 获取授权码 <br>
         * 若redirectUrl与所注册客户端的redirectUrl不一致，抛出异常
         *
         * @param clientId    客户端id
         * @param redirectUrl 重定向url
         * @return Authorization Code 授权码
         * @throws AuthorizationException 授权失败
         */
        @NonNull
        public static String createBasicScopeAuthorizationCode(@NonNull String clientId,
                                                               @NonNull String redirectUrl) throws AuthorizationException {
            if (isLogin() && agreeAuthorize(clientId)) {
                return OpenAuthHelper.createBasicScopeAuthorizationCode(clientId, redirectUrl, getUserId());
            }
            throw AuthorizationException.privilegeGrantFailed();
        }

        /**
         * 客户端id有效，能够授权
         *
         * @param clientId 客户端id
         * @return 是否能够授权
         */
        public static boolean agreeAuthorize(@NonNull String clientId) {
            return OpenAuthHelper.findClient(clientId) != null;
        }

        /**
         * 根据clientId获取注册client的详细信息
         *
         * @param clientId 客户端id
         * @return 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
         */
        public static ClientDetails findClient(@NonNull String clientId) {
            return OpenAuthHelper.findClient(clientId);
        }

        /**
         * 根据clientId获取注册client的RedirectUrl
         *
         * @param clientId 客户端id
         * @return RedirectUrl 重定向地址
         */
        public static String getRedirectUrl(@NonNull String clientId) {
            return OpenAuthHelper.findClient(clientId).getRedirectUrl();
        }

        public static void removeAuthorizedDevice(@NonNull String id) throws NotLoginException {
            removeAuthorizedDevice(getUserId(), id);
        }

        public static void removeAuthorizedDevice(@NonNull Object userId,
                                                  @NonNull String id) {
            OpenAuthHelper.removeAuthorizedDevice(userId, id);
        }

        public static void removeAllAuthorizedDevice() throws NotLoginException {
            removeAllAuthorizedDevice(getUserId());
        }

        public static void removeAllAuthorizedDevice(@NonNull Object userId) {
            OpenAuthHelper.removeAllAuthorizedDevice(userId);
        }

        public static List<AuthorizedDeviceDetails> getAllAuthorizedDeviceDetails() throws NotLoginException {
            return getAllAuthorizedDeviceDetails(getUserId());
        }

        public static List<AuthorizedDeviceDetails> getAllAuthorizedDeviceDetails(@NonNull Object userId) {
            return OpenAuthHelper.getAllAuthorizedDeviceDetails(userId);
        }

        /**
         * 根据clientId注销client
         *
         * @param clientId 客户端id
         */
        public static void deleteClient(@NonNull String clientId) {
            OpenAuthHelper.deleteClient(clientId);
        }

        /**
         * 注册一个客户端
         *
         * @return 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
         */
        public static ClientDetails clientRegister() {
            return OpenAuthHelper.clientRegister("DefaultClientName", null);
        }

        /**
         * 注册一个客户端
         *
         * @param clientName  客户端名
         * @param redirectUrl 回调地址
         * @return 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
         */
        public static ClientDetails clientRegister(@NonNull String clientName,
                                                   @NonNull String redirectUrl) {
            return OpenAuthHelper.clientRegister(clientName, redirectUrl);
        }

        /**
         * 注册一个客户端
         *
         * @param clientId    客户端id
         * @param clientName  客户端名
         * @param redirectUrl 回调地址
         * @return 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
         */
        public static ClientDetails clientRegister(@NonNull String clientId,
                                                   @NonNull String clientName,
                                                   @NonNull String redirectUrl) {
            return OpenAuthHelper.clientRegister(clientId, clientName, redirectUrl);
        }

        /**
         * 注册一个客户端
         *
         * @param clientId     客户端id
         * @param clientSecret 客户端密钥
         * @param clientName   客户端名
         * @param redirectUrl  回调地址
         * @return 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
         */
        public static ClientDetails clientRegister(@NonNull String clientId,
                                                   @NonNull String clientSecret,
                                                   @NonNull String clientName,
                                                   @NonNull String redirectUrl) {
            return OpenAuthHelper.clientRegister(clientId, clientSecret, clientName, redirectUrl);
        }

    }

    // **************************************     RSA      ************************************** //

    /**
     * @since 1.2.0
     */
    public static class RSA {

        private RSA() {}

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
        public static void rsaAutoRefresh() {
            AuthzRSAManager.setAuto(true);
        }

        /**
         * 关闭自动刷新RSA，需要额外指定公钥私钥对
         */
        public static void closeRSAAutoRefreshAndSetup(String publicKey,
                                                       String privateKey) {
            AuthzRSAManager.setAuKeyPair(publicKey, privateKey);
        }

    }

    // **************************************     缓存      ************************************** //

    /**
     * <li>1、在开启Redis时为L2Cache(二级缓存)，默认情况下为普通的带时间策略的缓存</li>
     * <li>
     * 2、缓存策略：
     * <ul>2.1、若没有指定时间，默认为永久</ul>
     * <ul>2.2、在指定时间后，过期会删除key</ul>
     * <ul>2.3、若指定时间，L2环境下，本地时间会小于redis所存留的时间，在每次访问时，本地时间会重新计时，且成为热点key，加载速度更快</ul>
     * <ul>2.4、若指定时间，则会在redis里存一份，本地存一份，若其他实例修改，则会同步修改（默认实现为redis的消息队列）</ul>
     * </li>
     * <li>3.L2Cache开启时会默认创建缓存消息通道，在修改其中</li>
     *
     * @since 1.2.0
     */
    public static class Cache {

        private Cache() {}

        public <E> void set(String key,
                            E element) {
            cache.set(key, element);
        }

        public <E> void set(String key,
                            E element,
                            long time,
                            TimeUnit unit) {
            cache.set(key, element, time, unit);
        }

        public <E> void set(String key,
                            E element,
                            String time) {
            cache.set(key, element, time);
        }

        public void delete(String... keys) {
            cache.del(keys);
        }

        public void delete(Collection<String> keys) {
            if (keys instanceof Set) {cache.del((Set<String>) keys);} else {delete(new HashSet<>(keys));}
        }

        public Map<String, Object> get(Collection<String> keys) {
            if (keys instanceof Set) {return cache.get((Set<String>) keys);} else {
                return cache.get(new HashSet<>(keys));
            }
        }

        public Object get(String key) {
            return cache.get(key);
        }

        /**
         * redis修改时调用 <br>
         * 重新加载所有缓存
         */
        public static void reloadCache() {
            cache.reload();
        }

        /**
         * redis修改时调用 <br>
         * 重新加载所有缓存
         */
        public static void reloadCache(String... keys) {
            cache.reload(keys);
        }

        /**
         * redis修改时调用 <br>
         * 重新加载指定的缓存
         */
        public static void reloadCache(Collection<String> keys) {
            cache.reload(keys);
        }

    }

    // *************************************     回调函数      ************************************* //

    public static class Callback {

        private Callback() {}

        /**
         * 设置封禁和解封时的回调函数 「或者」 继承{@link RateLimitCallback} 将其注册入Spring容器中
         *
         * @param rateLimitCallback 封禁和解封时的回调函数
         */
        public static void setRateLimitCallback(RateLimitCallback rateLimitCallback) {
            Httpd.setRateLimitCallback(rateLimitCallback);
        }

        /**
         * 设置成功授权获得授权码时的回调函数
         *
         * @param createAuthorizationCodeCallback 成功授权获得授权码时的回调函数
         */
        public static void setAuthorizationCallback(AuthorizationCallback authorizationCallback) {
            OpenAuthHelper.setAuthorizationCallback(authorizationCallback);
        }
    }

    // *************************************     api权限、数据权限、rate-limit 动态修改      ************************************* //

    @Nullable
    public static Object authzModify(@NonNull AuthzModifier authzModifier) {
        return modify(authzModifier);
    }

    private AuHelper() {
    }

}
