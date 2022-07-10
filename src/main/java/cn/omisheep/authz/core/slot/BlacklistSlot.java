package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.Blacklist;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.0
 */
@Order(5)
@SuppressWarnings("all")
public class BlacklistSlot implements Slot {
    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        boolean check = Blacklist.check(httpMeta.getIp(), httpMeta.getToken());
        if (check) return;
        error.error(ExceptionStatus.REQUEST_EXCEPTION);
        return;
    }
}
