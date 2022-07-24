package cn.omisheep.authz.support.http.handler;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.support.util.SupportUtils;
import cn.omisheep.commons.util.web.JSONUtils;
import lombok.Getter;
import lombok.SneakyThrows;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
public class DocsDescHandler implements WebHandler {

    @Getter
    private static final HashMap<String, String> info = new HashMap<>();
    private static final String                  _info;

    static {
        info.put("/v1", "查看所有接口文档");
        info.put("/v1/docs", "查看所有信息");
        _info = JSONUtils.toPrettyJSONString(info);
    }

    @Override
    public boolean match(String path) {
        return path.equals("/v1");
    }

    @SneakyThrows
    @Override
    public void process(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, String path, boolean auth) {
        SupportUtils.toJSON(response, _info);
    }
}
