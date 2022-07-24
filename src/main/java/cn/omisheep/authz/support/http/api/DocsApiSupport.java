package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.web.entity.Result;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class DocsApiSupport implements ApiSupport {

    @Get(value = "/docs")
    public Result version(Docs docs) {
        return Result.SUCCESS.data(docs);
    }

}
