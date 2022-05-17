package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import lombok.Getter;

import java.util.Date;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Getter
public class RequestInfo {
    private final String ip;
    private final Date   lastRequestTime;

    private RequestInfo(String ip, Date lastRequestTime) {
        this.ip              = ip;
        this.lastRequestTime = lastRequestTime;
    }

    public static RequestInfo of(HttpMeta httpMeta) {
        return new RequestInfo(httpMeta.getIp(), httpMeta.getDate());
    }
}
