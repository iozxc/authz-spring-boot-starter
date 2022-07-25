package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.support.entity.Cloud;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class CloudApiSupport implements ApiSupport {

    @Get(value = "/cloud")
    public Cloud version(Cloud cloud) {
        return cloud;
    }

}
