package cn.omisheep.authz.support.http.handler;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.commons.util.web.JSONUtils;
import lombok.SneakyThrows;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
public class DocsHandler implements WebHandler {

    private final Docs docs;

    public DocsHandler() {
        docs = AUtils.getBean(Docs.class);
    }

    @Override
    public boolean match(String path) {
        return path.equals("/v1/docs");
    }

    @SneakyThrows
    @Override
    public void process(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, String path) {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().println(JSONUtils.toPrettyJSONString(docs));
    }
}
