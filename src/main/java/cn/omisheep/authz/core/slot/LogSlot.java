package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.LogUtils;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Order
public class LogSlot implements Slot {

    @Override
    public boolean must() {
        return true;
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) {
        LogUtils.exportLogsFromRequest(httpMeta.getRequest());
        return true;
    }
}
