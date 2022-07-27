package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface Device extends Map<Object, Object>, java.io.Serializable {

    String getDeviceType();

    String getDeviceId();

    Date getLastRequestTime();

    Long getLastRequestTimeLong();

    String getIp();

    Device setDeviceType(String type);

    Device setLastRequestTime(Date lastRequestTime);

    Device setDeviceId(String id);

    Device setIp(String ip);
}
