package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Order(50)
public class OAuthSlot implements Slot {
    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        Token token = httpMeta.getToken();
        System.out.println(token);
    }
}
