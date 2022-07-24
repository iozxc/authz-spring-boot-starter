package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Param;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.web.entity.Result;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class StandardApiSupport implements ApiSupport {

    public StandardApiSupport(AuthzProperties properties) {
    }

    @Get(value = "/echo")
    public Result version(@Param String msg) {
        return Result.SUCCESS.data(msg);
    }

    @Post(value = "/operate")
    public Result operate(@JSON AuthzModifier modifier) {
        if (modifier == null) return Result.FAIL.data();
        return AuthzManager.operate(modifier);
    }

    @Get(value = "/version")
    public Result version() {
        return Result.SUCCESS.data(AuthzVersion.getVersion());
    }

}
