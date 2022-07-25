package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.handler.ApiHandler;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class DocsApiSupport implements ApiSupport {

    private static final Help help;

    static {
        help = new Help();
        HashMap<String, String> map = new HashMap<>();
        ApiHandler.getApi().forEach((k, v) -> map.put(k, v.getDesc()));
        help.apiDesc = map;
    }

    @Data
    public static class Help {
        @JsonProperty(index = 1)
        private String                          base = "/authz-api/v1";
        @JsonProperty(index = 2)
        private Map<String, String>             apiDesc;
        @JsonProperty(index = 3)
        private Map<String, ApiHandler.ApiInfo> api  = ApiHandler.getApi();
    }

    @Get(value = "", desc = "查看所有接口文档")
    public Help help() {
        return help;
    }

    @Get(value = "/docs", desc = "查看所有信息")
    public Docs version(Docs docs) {
        return docs;
    }

}
