package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import org.springframework.web.method.HandlerMethod;

import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Order(30)
@SuppressWarnings("all")
public class IPRangeSlot implements Slot {
    private final PermissionDict permissionDict;

    public IPRangeSlot(PermissionDict permissionDict) {
        this.permissionDict = permissionDict;
    }

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        try {
            if (permissionDict.isSupportNative()) {
                if (httpMeta.getIp().equals("0:0:0:0:0:0:0:1") || httpMeta.getIp().equals("127.0.0.1")) {
                    //0:0:0:0:0:0:0:1  127.0.0.1
                    return;
                }
            }
            if (!isPermittedRequest(httpMeta.getIp(), permissionDict.getGlobalAllow(), permissionDict.getGlobalDeny())) {
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }
            IPRangeMeta ipRangeMeta = permissionDict.getIPRange().get(httpMeta.getMethod()).get(httpMeta.getApi());
            if (ipRangeMeta != null && !isPermittedRequest(httpMeta.getIp(), ipRangeMeta.getAllow(), ipRangeMeta.getDeny())) {
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }
            return;
        } catch (Exception e) {
            return;
        }
    }

    public boolean isPermittedRequest(String remoteAddress, Set<IPRange> allowList, Set<IPRange> denyList) {
        boolean ipV6 = remoteAddress.indexOf(':') != -1;

        if (ipV6) {
            return (denyList.size() == 0 && allowList.size() == 0);
        }

        IPAddress ipAddress = new IPAddress(remoteAddress);

        for (IPRange range : denyList) {
            if (range.isIPAddressInRange(ipAddress)) {
                return false;
            }
        }

        if (allowList.size() > 0) {
            for (IPRange range : allowList) {
                if (range.isIPAddressInRange(ipAddress)) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }
}
