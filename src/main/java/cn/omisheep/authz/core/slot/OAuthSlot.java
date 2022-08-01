package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
import cn.omisheep.authz.core.tk.GrantType;
import org.springframework.web.method.HandlerMethod;

import java.util.Set;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Order(50)
public class OAuthSlot implements Slot {

    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        if (!httpMeta.hasToken()) return;
        String clientId = httpMeta.getToken().getClientId();
        if (clientId == null) return;
        String      path   = httpMeta.getApi();
        String      method = httpMeta.getMethod();
        GrantType   type   = httpMeta.getToken().getGrantType();
        Set<String> scope  = httpMeta.getScope();
        if (!OpenAuthDict.target(path, method, type, scope)) {
            error.error(ExceptionStatus.SCOPE_EXCEPTION_OR_TYPE_ERROR);
        }
    }

}
