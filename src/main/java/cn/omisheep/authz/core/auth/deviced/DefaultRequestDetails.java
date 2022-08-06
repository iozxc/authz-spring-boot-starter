package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.IP;
import static cn.omisheep.authz.core.config.Constants.LAST_REQUEST_TIME;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class DefaultRequestDetails extends DefaultDevice implements RequestDetails {

    private static final long serialVersionUID = -2158329370706404354L;

    @Override
    public Date getLastRequestTime() {
        return getDate(LAST_REQUEST_TIME);
    }

    @Override
    public Long getLastRequestTimeLong() {
        return getLong(LAST_REQUEST_TIME);
    }


    @Override
    public DefaultRequestDetails setLastRequestTime(Date lastRequestTime) {
        setDate(LAST_REQUEST_TIME, lastRequestTime);
        return this;
    }

    @Override
    public String getIp() {
        return getString(IP);
    }

    @Override
    public DefaultRequestDetails setIp(String ip) {
        setValue(IP, ip);
        return this;
    }

}
