package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.NotLoginException;
import cn.omisheep.authz.core.auth.deviced.DeviceDetails;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
     * @return 所有当前有效登录用户的用户id, 当开启redis缓存时，userId返回为String数组
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
        return userDevicesDict.listDevicesByUserId(AuHelper.getUserId());
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
}
