package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.support.entity.Cloud;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.web.entity.Result;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class CloudApiSupport implements ApiSupport {

    @Get(value = "/cloud")
    public Result version(Cloud cloud) {
        return Result.SUCCESS.data(cloud);
    }

}
