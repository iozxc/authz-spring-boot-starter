package cn.omisheep.authz.core.auth.deviced;


import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class DefaultDevice extends AuMap implements Device {
    private static final long serialVersionUID = 3561879223319144385L;

    public DefaultDevice() {
        super();
    }

    @Override
    public String getDeviceType() {
        return getString(DEVICE_TYPE);
    }

    @Override
    public Device setDeviceType(String type) {
        setValue(DEVICE_TYPE, type);
        return this;
    }

    @Override
    public String getDeviceId() {
        return getString(DEVICE_ID);
    }

    @Override
    public Device setDeviceId(String id) {
        setValue(DEVICE_ID, id);
        return this;
    }

    @Override
    public Date getLastRequestTime() {
        return getDate(LAST_REQUEST_TIME);
    }

    @Override
    public Long getLastRequestTimeLong() {
        return getLong(LAST_REQUEST_TIME);
    }

    @Override
    public Device setLastRequestTime(Date lastRequestTime) {
        setDate(LAST_REQUEST_TIME, lastRequestTime);
        return this;
    }

    @Override
    public String getIp() {
        return getString(IP);
    }

    @Override
    public Device setIp(String ip) {
        setValue(IP, ip);
        return this;
    }
}
