package cn.omisheep.authz.support.http.handler;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
public interface WebHandler {
    boolean match(String path);

    default boolean requireLogin() {
        return true;
    }

    void process(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, String path, boolean auth);

}
