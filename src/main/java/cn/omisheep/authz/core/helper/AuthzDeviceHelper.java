package cn.omisheep.authz.core.helper;

import cn.omisheep.authz.core.auth.deviced.DeviceDetails;
import cn.omisheep.commons.util.TimeUtils;
import org.springframework.lang.NonNull;

import java.util.List;

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

}
