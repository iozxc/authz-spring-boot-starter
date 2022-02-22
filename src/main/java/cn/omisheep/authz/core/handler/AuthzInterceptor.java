package cn.omisheep.authz.core.handler;

import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.auth.AuthzDefender;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.LogUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@SuppressWarnings("all")
public class AuthzInterceptor implements HandlerInterceptor {

    private final AuthzDefender auDefender;

    public AuthzInterceptor(AuthzDefender auDefender) {
        this.auDefender = auDefender;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return false;
        }
        HandlerMethod hm = (HandlerMethod) handler;

        // 状态获取初始化
        HttpMeta httpMeta = (HttpMeta) request.getAttribute(Constants.HTTP_META);

        // 如果是OPTIONS请求，直接放行
        if (httpMeta.isMethod(Constants.OPTIONS)) return true;

        if (!auDefender.requireProtect(httpMeta.getMethod(), httpMeta.getApi())) {
            LogUtils.exportLogsFromRequest();
            return true;
        }

        /*
              token鉴权
                （1）如果cookie中没有atkn，则根据config，判断是否去拦截。
                    <1> 开启「无cookie则拦截」，则会返回需要登录的异常信息，不通过。
                    <2> 关闭「无cookie则拦截」，则会接着判断接口是否需要权限，如果不需要权限，如any，则通过。
                （2）cookie中有 atkn 取出并解析，
                    正常则通过，
                    如果过期，则抛出异常「accessToken过期」，这时需用refreshToken刷新accessToken（有提供接口）。
                        【此时不管接口是否需要权限，都会返回accessToken过期】
                    如果refreshToken过期，那么返回refresh失败，告诉前端，需要重新登录，去获取新的tokenPair。
                        【此时不管接口是否需要权限，都会返回refreshToken过期】

                1. cookie是否存在
                2. 接口是否为any权限或者none
                3. token解析是否正确
                4. 用户是否登录于系统中
                    1） 验证userId 若不存在则需重新登录
                    （此时token正确，但是系统不存在，意味着系统重启了，或者redis重启了）
                    2） 验证device 若不存在，但是userId存在，
                    3） 验证tokenId 若不匹配 意味着
                5. 权限判断

         */
        boolean flag = auDefender.verify(httpMeta);

        LogUtils.exportLogsFromRequest();
        return flag;
    }

}
