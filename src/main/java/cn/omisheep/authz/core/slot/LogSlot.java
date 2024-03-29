package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class LogSlot implements Slot {

    @Override
    public boolean must() {
        return true;
    }

    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        httpMeta.exportLog();
    }
}
