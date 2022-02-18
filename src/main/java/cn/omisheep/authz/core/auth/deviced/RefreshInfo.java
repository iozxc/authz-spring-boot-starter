package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class RefreshInfo extends DefaultDevice {

    public static final String EXPIRATION = "rex";
    private static final long serialVersionUID = 630388187461710252L;

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
