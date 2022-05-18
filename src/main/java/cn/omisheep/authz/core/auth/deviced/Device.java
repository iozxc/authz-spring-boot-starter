package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface Device extends Map<Object, Object>, java.io.Serializable {

    String TYPE              = "type";
    String ID                = "id";
    String LAST_REQUEST_TIME = "lrt";
    String IP                = "ip";

    String getType();

    String getId();

    Date getLastRequestTime();

    String getIp();

    Device setType(String type);

    Device setLastRequestTime(Date lastRequestTime);

    Device setId(String id);

    Device setIp(String ip);
}
