package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class RefreshInfo extends DefaultDevice {
    private static final long serialVersionUID = 630388187461710252L;

    public static final String EXPIRATION = "rex";

    public RefreshInfo() {
        super();
    }

    public RefreshInfo setDevice(Device device) {
        putAll(device);
        return this;
    }

    public Device getDevice() {
        return this;
    }

    public RefreshInfo setExpiration(Date expirationDate) {
        setDate(EXPIRATION, expirationDate);
        return this;
    }

    public Date getExpiration() {
        return getDate(EXPIRATION);
    }

    public long getExpirationVal() {
        return Long.parseLong((String) get(EXPIRATION));
    }

}
