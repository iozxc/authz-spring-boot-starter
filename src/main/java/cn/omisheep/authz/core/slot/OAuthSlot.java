package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.AccessToken;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Order(50)
public class OAuthSlot implements Slot {
    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        AccessToken token = httpMeta.getToken(); // todo
        System.out.println(token);
    }
}
