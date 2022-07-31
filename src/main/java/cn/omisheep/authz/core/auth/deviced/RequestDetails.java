package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public interface RequestDetails {

    Date getLastRequestTime();

    Long getLastRequestTimeLong();

    DefaultRequestDetails setLastRequestTime(Date lastRequestTime);

    String getIp();

    DefaultRequestDetails setIp(String ip);

}
