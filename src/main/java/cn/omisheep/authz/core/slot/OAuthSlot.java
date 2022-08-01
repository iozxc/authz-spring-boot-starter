package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Order(50)
public class OAuthSlot implements Slot {

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        String clientId = httpMeta.getToken().getClientId();
        if (clientId==null) return;
        if (!OpenAuthDict.hasScope(httpMeta.getApi(), httpMeta.getMethod(), httpMeta.getScope())) {
            error.error(ExceptionStatus.SCOPE_EXCEPTION);
        }
    }

}
