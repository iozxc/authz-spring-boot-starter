package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzFactory;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.commons.util.web.JSONUtils;
import cn.omisheep.web.entity.Result;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class StandardApiSupport implements ApiSupport {

    public StandardApiSupport(AuthzProperties properties) {
    }

    @Post(value = "/operate")
    public Result login(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta) {
        AuthzModifier modifier = JSONUtils.parseJSON(httpMeta.getBody(), AuthzModifier.class);
        if (modifier == null) return Result.FAIL.data();
        return AuthzFactory.operate(modifier);
    }

    @Get(value = "/version")
    public Result version(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta) {
        return Result.SUCCESS.data(AuthzVersion.getVersion());
    }

}
