package cn.omisheep.authz.core.auth.deviced;


import java.util.Date;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class DefaultDevice extends AuMap implements Device {

    private static final long serialVersionUID = 3561879223319144385L;

    public DefaultDevice() {
        super();
    }

    public DefaultDevice(Map<Object, Object> map) {
        super(map);
    }

    @Override
    public String getType() {
        return getString(TYPE);
    }

    @Override
    public Device setType(String type) {
        setValue(TYPE, type);
        return this;
    }

    @Override
    public String getId() {
        return getString(ID);
    }

    @Override
    public Device setId(String id) {
        setValue(ID, id);
        return this;
    }

    @Override
    public Date getLastRequestTime() {
        return getDate(LAST_REQUEST_TIME);
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
