package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.auth.deviced.DeviceCountInfo;
import cn.omisheep.authz.core.auth.deviced.DeviceDetails;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static cn.omisheep.authz.AuHelper.getUserId;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class AuthzDeviceHelper extends BaseHelper {
    private AuthzDeviceHelper() {
        throw new UnsupportedOperationException();
    }

    /**
     * 所有【在线/活跃】用户详细设备信息
     *
     * @param ms 时间间隔(ms)
     * @return 用户设备list
     */
    @NonNull
    public static List<DeviceDetails> getActiveDevices(long ms) {
        return userDevicesDict.listActiveUserDevices(ms);
    }

    /**
     * 所有【在线/活跃】用户详细设备信息
     *
     * @param time 时间间隔(ms)
     * @return 用户设备list
     */
    @NonNull
    public static List<DeviceDetails> getActiveDevices(String time) {
        return getActiveDevices(TimeUtils.parseTimeValue(time));
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param time 时间间隔
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> getActiveUserIdList(@NonNull String time) {
        return getActiveUserIdList(TimeUtils.parseTimeValue(time));
    }

    /**
     * 所有【在线/活跃】用户Id数组
     *
     * @param ms 时间间隔(ms)
     * @return 用户id数组
     */
    @NonNull
    public static List<Object> getActiveUserIdList(long ms) {
        return getActiveDevices(ms).stream().map(DeviceDetails::getUserId).distinct().collect(Collectors.toList());
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
     * @return 所有当前有效登录用户的用户id
     */
    @NonNull
    public static List<Object> getAllUserId() {
        return userDevicesDict.listUserId();
    }

    /**
     * 获得指定设备信息
     *
     * @param userId 指定userId
     * @return 设备信息
     */
    @Nullable
    public static DeviceDetails getDeviceByUserIdAndDeviceTypeAndDeviceId(@NonNull Object userId,
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
    public static List<DeviceDetails> getAllDeviceFromCurrentUser() throws NotLoginException {
        return userDevicesDict.listDevicesByUserId(getUserId());
    }

    /**
     * 获得指定userId的所有设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @NonNull
    public static List<DeviceDetails> getAllDeviceByUserId(@NonNull Object userId) {
        return userDevicesDict.listDevicesByUserId(userId);
    }

    /**
     * 获得指定userId的所有设备信息
     *
     * @param userId 指定userId
     * @return 所有设备信息
     */
    @NonNull
    public static List<DeviceDetails> getAllDeviceByUserIdAndDeviceType(@NonNull Object userId,
                                                                        @NonNull String deviceType) {
        return userDevicesDict.listDevicesByUserId(userId).stream().filter(
                device -> device.getDeviceType().equals(deviceType)).collect(Collectors.toList());
    }

    /**
     * 查询所有用户信息，一个map userId->设备信息列表
     *
     * @return 一个map userId->设备信息列表
     */
    @NonNull
    public static Map<Object, List<DeviceDetails>> getAllUsersDevices() {
        HashMap<Object, List<DeviceDetails>> map = new HashMap<>();
        AuHelper.getAllUserId().forEach(userId -> map.put(userId, getAllDeviceByUserId(userId)));
        return map;
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
        addDeviceTypesTotalLimitAt(getUserId(), types, total);
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
        userDevicesDict.addDeviceTypesTotalLimit(userId, types, total);
    }

    /**
     * 获得一个可修改的 DeviceTypesTotalLimit list
     * count >= 1 or count = -1
     *
     * @param userId 用户id
     */
    public static List<DeviceCountInfo> getOrUpdateDeviceTypesTotalLimitAt(@NonNull Object userId) {
        return userDevicesDict.getOrUpdateDeviceTypesTotalLimit(userId);
    }


    /**
     * 获得一个可修改的 DeviceTypesTotalLimit list
     * count >= 1 or count = -1
     */
    public static List<DeviceCountInfo> getOrUpdateDeviceTypesTotalLimit() throws NotLoginException {
        return userDevicesDict.getOrUpdateDeviceTypesTotalLimit(getUserId());
    }

    /**
     * 登录设备总数默不做限制【total为-1不做限制，最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param count 数量
     */
    public static void changeMaximumTotalDevice(int count) throws NotLoginException {
        changeMaximumTotalDeviceAt(getUserId(), count);
    }

    /**
     * 登录设备总数默不做限制【total为-1不做限制，最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param userId 用户id
     * @param count  数量
     */
    public static void changeMaximumTotalDeviceAt(@NonNull Object userId,
                                                  int count) {
        userDevicesDict.changeMaximumTotalDevice(userId, count);
    }

    /**
     * 同类型设备最多登录数 默认 1个【count最小为1】，超出会挤出最长时间未访问的设备。
     * count >= 1
     *
     * @param count 数量
     */
    public static void changeMaximumTotalSameTypeDevice(int count) throws NotLoginException {
        changeMaximumTotalSameTypeDeviceAt(getUserId(), count);
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
        userDevicesDict.changeMaximumTotalSameTypeDevice(userId, count);
    }


}
