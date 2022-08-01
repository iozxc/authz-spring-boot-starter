package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.web.method.HandlerMethod;

import static cn.omisheep.authz.core.config.Constants.OPTIONS;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Order(0)
public class FilterSlot implements Slot {
    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        if (httpMeta.isMethod(OPTIONS) || httpMeta.isIgnore()) {
            error.error();
        }
    }
}
