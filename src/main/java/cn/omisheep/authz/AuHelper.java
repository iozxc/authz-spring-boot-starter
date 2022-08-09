package cn.omisheep.authz;

/*
                 _    _
    /\   v1.2   | |  | |
   /  \   _   _ | |_ | |__  _authz
  / /\ \ | | | || __|| '_ \ |_  /
 / ____ \| |_| || |_ | | | | / /
/_/    \_\\__,_| \__||_| |_|/___|
 */

import cn.omisheep.authz.core.*;
import cn.omisheep.authz.core.auth.deviced.DeviceCountInfo;
import cn.omisheep.authz.core.auth.deviced.DeviceDetails;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.callback.AuthorizationCallback;
import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.authz.core.codec.AuthzRSAManager;
import cn.omisheep.authz.core.helper.*;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.oauth.AuthorizationException;
import cn.omisheep.authz.core.oauth.AuthorizedDeviceDetails;
import cn.omisheep.authz.core.oauth.ClientDetails;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.tk.IssueToken;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static cn.omisheep.authz.core.AuthzManager.modify;

/**
 * 时间字符串均采用如下格式 <br>
 * "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒 用空格隔开
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.2
 * @since 1.0.0
 */
//@SuppressWarnings("all")
public class AuHelper extends BaseHelper {

    // **************************************     登录 & 用户设备      ************************************** //

    /**
     * 用户登录 <br>
     * <p>
     * 若线程绑定了Request，则登录成功之后会默认给请求返回Cookie <br>
     * 过期时间为AccessToken的过期时间，若不需要，请自行删除
     *
     * @param userId 用户id - 不为空
     * @return 授权后的IssueToken(accessToken以及refreshToken)
     */
    @NonNull
    public static IssueToken login(@NonNull Object userId) {
        return AuthzGranterHelper.grant(userId, null, null);
    }

    /**
     * 用户登录 <br>
     * <p>
     * 若线程绑定了Request，则登录成功之后会默认给请求返回Cookie <br>
     * 过期时间为AccessToken的过期时间，若不需要，请自行删除
     *
     * @param userId     用户id - 不为空
     * @param deviceType 设备系统类型 - 不为null 默认为user-agnet，若没有则为unknown
     * @return 授权后的IssueToken(accessToken以及refreshToken)
     */
    @NonNull
    public static IssueToken login(@NonNull Object userId,
                                   @NonNull String deviceType) {
        return login(userId, deviceType, null);
    }

    /**
     * 用户登录 <br>
     * <p>
     * 若线程绑定了Request，则登录成功之后会默认给请求返回Cookie <br>
     * 过期时间为AccessToken的过期时间，若不需要，请自行删除
     *
     * @param userId     用户id - 不为空
     * @param deviceType 设备系统类型 - 不为空 默认为user-agnet，若没有则为unknown
     * @param deviceId   设备id - 可为null
     * @return 授权后的IssueToken(accessToken以及refreshToken)
     */
    @NonNull
    public static IssueToken login(@NonNull Object userId,
                                   @NonNull String deviceType,
                                   @Nullable String deviceId) {
        return AuthzGranterHelper.grant(userId, deviceType, deviceId);
    }

    /**
     * access过期刷新接口。
     * refreshToken 为一次性的，刷新之后会失效
     * <p>
     * 如果使用单token，则直接使用accessToken即可，在accessToken过期时再重新登录。
     * <p>
     * 使用双token时，accessToken过期时，可以利用refreshToken在此接口中刷新获得一个新的accessToken。
     *
     * @param refreshToken 与accessToken一起授予的refreshToken
     * @return IssueToken  刷新获得新的IssueToken(accessToken以及refreshToken)
     * @throws RefreshTokenExpiredException refreshToken过期 {@link RefreshTokenExpiredException}
     * @throws TokenException               refreshToken异常 {@link TokenException}
     */
    @NonNull
    public static IssueToken refreshToken(@NonNull String refreshToken)
            throws RefreshTokenExpiredException, TokenException {
        return AuthzGranterHelper.refreshToken(refreshToken);
    }

    /**
     * 注销当前用户当前设备
     */
    public static void logout() throws NotLoginException {
        AuthzGranterHelper.logout();
    }

    /**
     * 注销当前用户所指定的类型的所有设备
     *
     * @param deviceType 指定设备类型
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static void logout(@NonNull String deviceType) throws NotLoginException {
        AuthzGranterHelper.logout(deviceType, null);
    }

    /**
     * 注销当前用户所指定的类型和id的设备
     *
     * @param deviceType 指定设备类型
     * @param deviceId   指定设备id
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static void logout(@NonNull String deviceType,
                              @Nullable String deviceId) throws NotLoginException {
        AuthzGranterHelper.logout(deviceType, deviceId);
    }

    /**
     * 注销当前用户所有设备
     *
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static void logoutAll() throws NotLoginException {
        AuthzGranterHelper.logoutAll();
    }

    /**
     * 注销指定用户所有设备，建议用于管理员，如果某用户想通过自己id注销自己，建议加上参数权限判断
     *
     * @param userId 用户id
     */
    public static void logoutAllAt(@NonNull Object userId) {
        AuthzGranterHelper.logoutAll(userId);
    }

    /**
     * 注销指定用户所指定的类型的所有设备
     *
     * @param userId     用户id
     * @param deviceType 指定设备类型
     */
    public static void logoutAt(@NonNull Object userId,
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
    public static void logoutAt(@NonNull Object userId,
                                @NonNull String deviceType,
                                @Nullable String deviceId) {
        AuthzGranterHelper.logout(userId, deviceType, deviceId);
    }

    /**
     * 退出当前用户指定登录标识的设备
     *
     * @param id 登录标识
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    public static void logoutById(String id) throws NotLoginException {
        AuthzGranterHelper.logoutById(getUserId(), id);
    }

    /**
     * 退出指定用户指定登录标识的设备
     *
     * @param userId 用户id
     * @param id     登录标识
     */
    public static void logoutById(Object userId,
                                  String id) {
        AuthzGranterHelper.logoutById(userId, id);
    }

    /**
     * 查询所有用户信息，一个map userId->设备信息列表
     *
     * @return 一个map userId->设备信息列表
     */
    @NonNull
    public static Map<Object, List<DeviceDetails>> getAllUserDevices() {
        return AuthzDeviceHelper.getAllUsersDevices();
    }

    /**
     * @return 所有当前有效登录用户的用户id
     */
    @NonNull
    public static List<Object> getAllUserId() {
        return AuthzDeviceHelper.getAllUserId();
    }

    /**
     * 当前访问用户的指定类型的所有设备
     *
     * @return 设备列表
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @NonNull
    public static List<DeviceDetails> getDevices(@NonNull String deviceType)
            throws NotLoginException {
        return AuthzDeviceHelper.getAllDeviceByUserIdAndDeviceType(getUserId(), deviceType);
    }

    /**
     * 当前访问用户的所有设备
     *
     * @return 设备列表
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @NonNull
    public static List<DeviceDetails> getDevices()
            throws NotLoginException {
        return AuthzDeviceHelper.getAllDeviceFromCurrentUser();
    }

    /**
     * 当前访问用户的设备
     *
     * @return 设备列表
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static DeviceDetails getDevice()
            throws NotLoginException {
        AccessToken token = getToken();
        return AuthzDeviceHelper.getDeviceByUserIdAndDeviceTypeAndDeviceId(token.getUserId(), token.getDeviceType(),
                                                                           token.getDeviceId());
    }

    /**
     * 指定用户的所有设备
     *
     * @return 设备列表
     */
    @NonNull
    public static List<DeviceDetails> getDevicesAt(@NonNull Object userId) {
        return AuthzDeviceHelper.getAllDeviceByUserId(userId);
    }

    /**
     * 指定用户的指定类型的所有设备
     *
     * @return 设备列表
     */
    @NonNull
    public static List<DeviceDetails> getDevicesAt(@NonNull Object userId,
                                                   @NonNull String deviceType) {
        return AuthzDeviceHelper.getAllDeviceByUserIdAndDeviceType(userId, deviceType);
    }

    /**
     * 获得指定设备信息
     *
     * @param userId 指定userId
     * @return 设备信息
     */
    @Nullable
    public static DeviceDetails getDeviceAt(@NonNull Object userId,
                                            @NonNull String deviceType,
                                            @Nullable String deviceId) {
        return AuthzDeviceHelper.getDeviceByUserIdAndDeviceTypeAndDeviceId(userId, deviceType, deviceId);
    }

    /**
     * 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1），超出会挤出最长时间未访问的设备。
     * count >= 1 or count = -1
     *
     * @param types deviceType
     * @param total 数量
     */
    public static void addDeviceTypesTotalLimit(@NonNull Collection<String> types,
                                                int total) throws NotLoginException {
        AuthzDeviceHelper.addDeviceTypesTotalLimit(types, total);
    }

    /**
     * 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1），超出会挤出最长时间未访问的设备。
     * count >= 1 or count = -1
     *
     * @param userId 用户id
     * @param types  deviceType
     * @param total  数量
     */
    public static void addDeviceTypesTotalLimitAt(@NonNull Object userId,
                                                  @NonNull Collection<String> types,
                                                  int total) {
        AuthzDeviceHelper.addDeviceTypesTotalLimitAt(userId, types, total);
    }

    /**
     * 获得当前用户 可修改的 DeviceTypesTotalLimit list
     * count >= 1 or count = -1
     */
    public static List<DeviceCountInfo> getOrUpdateDeviceTypesTotalLimit() throws NotLoginException {
        return AuthzDeviceHelper.getOrUpdateDeviceTypesTotalLimit();
    }

    /**
     * 获得任意用户 可修改的 DeviceTypesTotalLimit list
     * count >= 1 or count = -1
     *
     * @param userId 用户id
     */
    public static List<DeviceCountInfo> getOrUpdateDeviceTypesTotalLimitAt(@NonNull Object userId) {
        return AuthzDeviceHelper.getOrUpdateDeviceTypesTotalLimitAt(userId);
    }

    /**
     * 登录设备总数默不做限制【total为-1不做限制，最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param total 总数
     */
    public static void changeMaximumDeviceTotal(int total) throws NotLoginException {
        AuthzDeviceHelper.changeMaximumTotalDevice(total);
    }

    /**
     * 登录设备总数默不做限制【total为-1不做限制，最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param userId 用户id
     * @param total 总数
     */
    public static void changeMaximumTotalDeviceAt(@NonNull Object userId,
                                                  int total) {
        AuthzDeviceHelper.changeMaximumTotalDeviceAt(userId, total);
    }

    /**
     * 同类型设备最多登录数 默认 1个【count最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param total 总数
     */
    public static void changeMaximumTotalSameTypeDevice(int total) throws NotLoginException {
        AuthzDeviceHelper.changeMaximumTotalSameTypeDevice(total);
    }


    /**
     * 同类型设备最多登录数 默认 1个【count最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param userId 用户id
     * @param count  数量
     */
    public static void changeMaximumTotalSameTypeDeviceAt(@NonNull Object userId,
                                                          int count) {
        AuthzDeviceHelper.changeMaximumTotalSameTypeDeviceAt(userId, count);
    }

    // **************************************     状态&权限      ************************************** //

    /**
     * @return 当前请求是否登录 true为登录、false为未登录
     */
    public static boolean isLogin() {
        return AuthzStateHelper.isLogin();
    }

    /**
     * @param id 登录标识
     * @return 当前请求是否登录 true为登录、false为未登录
     */
    public static boolean isLoginById(@NonNull String id) {
        try {
            return AuthzStateHelper.isLogin(getUserId(), id);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @param id 登录标识
     * @return 当前请求是否登录 true为登录、false为未登录
     */
    public static boolean isLoginById(@NonNull Object userId,
                                      @NonNull String id) {
        return AuthzStateHelper.isLogin(userId, id);
    }

    /**
     * 若当前线程未绑定HttpRequest。则抛出 {@link ThreadWebEnvironmentException}
     *
     * @return 获得当前请求的HttpMeta信息
     * @throws ThreadWebEnvironmentException 线程Web环境异常
     */
    @NonNull
    public static HttpMeta getHttpMeta() throws ThreadWebEnvironmentException {
        return AuthzContext.getCurrentHttpMeta();
    }

    /**
     * @return 获得当前请求的Token信息
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @NonNull
    public static AccessToken getToken() throws NotLoginException {
        return AuthzContext.getCurrentToken();
    }

    /**
     * @return 获得当前请求的userId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @NonNull
    public static Object getUserId() throws NotLoginException {
        return AuthzContext.getCurrentToken().getUserId();
    }

    /**
     * @return 获得当前请求的deviceType
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @NonNull
    public static String getDeviceType() throws NotLoginException {
        return AuthzContext.getCurrentToken().getDeviceType();
    }

    /**
     * @return 获得当前请求的deviceId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static String getDeviceId() throws NotLoginException {
        return AuthzContext.getCurrentToken().getDeviceId();
    }

    /**
     * @return 获得当前请求的clientId
     * @throws NotLoginException 若未登录，抛出 {@link NotLoginException}
     */
    @Nullable
    public static String getClientId() throws NotLoginException {
        return AuthzContext.getCurrentToken().getClientId();
    }

    /**
     * @param role 所指定的角色
     * @return 判断当前请求用户是否有指定角色 若未登录返回false
     */
    public static boolean hasRole(@NonNull String... role) {
        return hasRoles(Arrays.asList(role));
    }

    /**
     * @param roles 所指定的角色
     * @return 判断当前请求用户是否有指定角色 若未登录返回false
     */
    public static boolean hasRoles(@NonNull List<String> roles) {
        return AuthzStateHelper.hasRoles(roles);
    }

    /**
     * @param permission 所指定的权限
     * @return 判断当前请求用户是否有指定角色 若未登录返回false
     */
    public static boolean hasPermission(@NonNull String... permission) {
        return hasPermissions(Arrays.asList(permission));
    }

    /**
     * @param permissions 所指定的权限
     * @return 判断当前请求用户是否有指定角色
     */
    public static boolean hasPermissions(@NonNull List<String> permissions) {
        return AuthzStateHelper.hasPermissions(permissions);
    }

    /**
     * @param scope 所指定的访问范围
     * @return 判断当前请求用户（oauth）是否有指定的访问权限
     */
    public static boolean hasScope(@NonNull String... scope) {
        return AuthzStateHelper.hasScope(Arrays.asList(scope));
    }

    /**
     * @param scope 所指定的访问范围
     * @return 判断当前请求用户（oauth）是否有指定的访问权限
     */
    public static boolean hasScope(@NonNull List<String> scope) {
        return AuthzStateHelper.hasScope(scope);
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
        return AuthzDeviceHelper.checkUserIsActive(userId, time);
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
        return AuthzDeviceHelper.checkUserIsActive(userId, ms);
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户数量
     *
     * @return 用户id列表
     */
    public static int getNumberOfActiveUser() {
        return getActiveUserIdList(60000L).size();
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param time 时间间隔
     * @return 用户id列表
     */
    public static int getNumberOfActiveUser(@NonNull String time) {
        return getActiveUserIdList(time).size();
    }

    /**
     * 所有【在线/活跃】用户数量
     *
     * @param ms 时间间隔(ms)
     * @return 用户id列表
     */
    public static int getNumberOfActiveUser(long ms) {
        return getActiveUserIdList(ms).size();
    }

    /**
     * 所有【在线/活跃】（默认60秒内）用户Id数组
     *
     * @return 用户id列表
     */
    @NonNull
    public static List<Object> getActiveUserIdList() {
        return getActiveUserIdList(60000L);
    }

    /**
     * 所有【在线/活跃】用户Id列表
     *
     * @param time 时间间隔
     * @return 用户id列表
     */
    @NonNull
    public static List<Object> getActiveUserIdList(@NonNull String time) {
        return AuthzDeviceHelper.getActiveUserIdList(time);
    }

    /**
     * 所有【在线/活跃】用户Id列表
     *
     * @param ms 时间间隔(ms)
     * @return 用户id列表
     */
    @NonNull
    public static List<Object> getActiveUserIdList(long ms) {
        return AuthzDeviceHelper.getActiveUserIdList(ms);
    }

    /**
     * 所有【在线/活跃】用户详细设备信息 （默认60秒内）
     *
     * @return 用户设备列表
     */
    @NonNull
    public static List<DeviceDetails> getActiveDevices() {
        return AuthzDeviceHelper.getActiveDevices(60000L);
    }

    /**
     * 所有【在线/活跃】用户详细设备信息
     *
     * @param ms 时间间隔(ms)
     * @return 用户设备列表
     */
    @NonNull
    public static List<DeviceDetails> getActiveDevices(long ms) {
        return AuthzDeviceHelper.getActiveDevices(ms);
    }

    /**
     * 所有【在线/活跃】用户详细设备信息
     *
     * @param time 时间字符串 "2d 3h 4m 5s 100ms"-> 2天3小时4分钟5秒100毫秒
     * @return 用户设备列表
     */
    @NonNull
    public static List<DeviceDetails> getActiveDevices(@NonNull String time) {
        return AuthzDeviceHelper.getActiveDevices(time);
    }

    // **************************************     黑名单操作      ************************************** //

    /**
     * 【添加、修改】封禁 ip time时间
     *
     * @param ip 封禁的ip
     * @param ms 毫秒
     */
    public static void denyIP(@NonNull String ip,
                              @NonNull long ms) {
        Blacklist.IP.update(ip, ms);
    }

    /**
     * 【添加、修改】封禁 ip time时间
     *
     * @param ip      封禁的ip
     * @param endDate 过期日期
     */
    public static void denyIP(@NonNull String ip,
                              @NonNull Date endDate) {
        Blacklist.IP.update(ip, endDate);
    }

    /**
     * 【添加、修改】封禁 ipRange网段 time时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param ms      毫秒
     */
    public static void denyIPRange(@NonNull String ipRange,
                                   @NonNull long ms) {

        Blacklist.IPRangeDeny.update(ipRange, ms);
    }

    /**
     * 【添加、修改】封禁 ipRange网段 time时间
     *
     * @param ipRange 封禁的ip范围 xx.xx.xx.xx/xx
     * @param endDate 过期日期
     */
    public static void denyIPRange(@NonNull String ipRange,
                                   @NonNull Date endDate) {
        Blacklist.IPRangeDeny.update(ipRange, endDate);
    }

    /**
     * 【添加、修改】封禁 device time时间
     *
     * @param userId 封禁的userId
     * @param ms     毫秒
     */
    public static void denyUser(@NonNull Object userId,
                                @NonNull long ms) {
        Blacklist.User.update(userId, null, null, ms);
    }

    /**
     * 【添加、修改】封禁 device time时间
     *
     * @param userId  封禁的userId
     * @param endDate 过期日期
     */
    public static void denyUser(@NonNull Object userId,
                                @NonNull Date endDate) {
        Blacklist.User.update(userId, null, null, endDate);
    }

    /**
     * 【添加、修改】封禁 封禁 time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param ms         毫秒
     */
    public static void denyDevice(@NonNull Object userId,
                                  @NonNull String deviceType,
                                  @NonNull long ms) {
        denyDevice(userId, deviceType, null, ms);
    }

    /**
     * 【添加、修改】封禁 封禁 time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param endDate    过期日期
     */
    public static void denyDevice(@NonNull Object userId,
                                  @NonNull String deviceType,
                                  @NonNull Date endDate) {
        denyDevice(userId, deviceType, null, endDate);
    }


    /**
     * 【添加、修改】封禁 设备 time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param deviceId   封禁的设备id
     * @param ms         毫秒
     */
    public static void denyDevice(@NonNull Object userId,
                                  @NonNull String deviceType,
                                  @Nullable String deviceId,
                                  @NonNull long ms) {
        Blacklist.User.update(userId, deviceType, deviceId, ms);
    }


    /**
     * 【添加、修改】封禁 设备 time时间
     *
     * @param userId     封禁的userId
     * @param deviceType 封禁的设备类型
     * @param deviceId   封禁的设备id
     * @param endDate    过期日期
     */
    public static void denyDevice(@NonNull Object userId,
                                  @NonNull String deviceType,
                                  @Nullable String deviceId,
                                  @NonNull Date endDate) {
        Blacklist.User.update(userId, deviceType, deviceId, endDate);
    }

    /**
     * 得到所有的 封禁的ip信息
     *
     * @return 得到所有的 封禁的ip信息
     */
    @NonNull
    public static Set<Blacklist.IP> getAllDenyIPInfo() {
        return Blacklist.IP.list();
    }

    /**
     * @return 得到封禁的ip信息
     */
    @Nullable
    public static Blacklist.IP getDenyIPInfo(String ip) {
        return Blacklist.IP.get(ip);
    }

    /**
     * @return 得到封禁的iprange信息
     */
    @NonNull
    public static Set<Blacklist.IPRangeDeny> getAllDenyIPRangeInfo() {
        return Blacklist.IPRangeDeny.list();
    }

    /**
     * @return 获得封禁用户的信息
     */
    @NonNull
    public static Set<Blacklist.User> getAllDenyUserInfo() {
        return Blacklist.User.list();
    }

    /**
     * @param userId 指定用户id
     * @return 获得指定的封禁用户的信息
     */
    @NonNull
    public static Set<Blacklist.User> getDenyUserAndDeviceInfo(@NonNull Object userId) {
        return Blacklist.User.list(userId);
    }

    /**
     * @param userId 指定用户id
     * @return 获得指定的封禁用户的信息
     */
    @Nullable
    public static Blacklist.User getDenyUserInfo(@NonNull Object userId) {
        return Blacklist.User.getUser(userId);
    }

    /**
     * @param userId     指定用户id
     * @param deviceType 指定设备deviceType
     * @param deviceId   指定设备deviceId
     * @return 封禁信息
     */
    @Nullable
    public static Blacklist.User getDenyDeviceInfo(@NonNull Object userId,
                                                   @NonNull String deviceType,
                                                   @Nullable String deviceId) {
        return Blacklist.User.getDevice(userId, deviceType, deviceId);
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
    public static void removeDenyDevice(@NonNull Object userId,
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
    public static void removeDenyDevice(@NonNull Object userId,
                                        @NonNull String deviceType,
                                        @NonNull String deviceId) {
        Blacklist.User.remove(userId, deviceType, deviceId);
    }

    // **************************************     OpenAuth 2.0      ************************************** //

    /**
     * <li>1.注册客户端 {@link #clientRegister(String, String)} -> 返回客户端信息（客户端id，客户端name，客户端密钥，重定向url）</li>
     * <li>2.获取授权码 {@link #createAuthorizationCode(String, String, String)} -> 客户端id+登录用户+权限范围 、获得登录用户的授权码</li>
     * <li>3.验证授权码 {@link #authorizeByCode(String, String, String)}-> 利用授权码去获得IssueToken</li>
     * <li>or 3.登录授权 {@link #authorizeByPassword(String, String, String)}-> 登录即可获得IssueToken</li>
     *
     * @since 1.2.0
     */
    public static class OpenAuth {

        /**
         * 授权码登录 （授权类型 authorization_code）- 不需要登录 <br>
         * <p>
         * 验证授权码是否有效，成功返回IssueToken
         *
         * @param clientId          客户端id
         * @param clientSecret      客户端密钥
         * @param authorizationCode 授权码
         * @return 授权后的IssueToken(accessToken以及refreshToken)
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
         * @return 授权后的IssueToken(accessToken以及refreshToken)
         * @throws AuthorizationException 验证失败，客户端密码错误 或 未登录
         */
        @Nullable
        public static IssueToken authorizeByPassword(@NonNull String clientId,
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
         * @return 授权后的IssueToken(accessToken以及refreshToken)
         * @throws AuthorizationException 验证失败，客户端密码错误 或 未登录
         */
        @Nullable
        public static IssueToken authorizeByPassword(@NonNull String clientId,
                                                     @NonNull String clientSecret,
                                                     @NonNull String scope) throws AuthorizationException {
            return OpenAuthHelper.authorizeByPassword(clientId, clientSecret, scope, getUserId());
        }

        /**
         * 客户端登录 （授权类型 client_credentials）- 不需要登录 <br>
         * <p>
         * 成功返回IssueToken
         *
         * @param clientId     客户端id
         * @param clientSecret 客户端密钥
         * @param scope        授权范围
         * @return 授权后的IssueToken(accessToken以及refreshToken)
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
        @NonNull
        public static ClientDetails findClient(@NonNull String clientId) {
            return OpenAuthHelper.findClient(clientId);
        }

        /**
         * 根据clientId获取注册client的RedirectUrl
         *
         * @param clientId 客户端id
         * @return RedirectUrl 重定向地址
         */
        @NonNull
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

        @NonNull
        public static List<AuthorizedDeviceDetails> getAuthorizedDeviceDetails() throws NotLoginException {
            return getAuthorizedDeviceDetailsAt(getUserId());
        }

        @NonNull
        public static List<AuthorizedDeviceDetails> getAuthorizedDeviceDetailsAt(@NonNull Object userId) {
            return OpenAuthHelper.getAuthorizedDeviceDetailsAt(userId);
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
         * @param authorizationCallback 成功授权获得授权码时的回调函数
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
        throw new UnsupportedOperationException();
    }

}
