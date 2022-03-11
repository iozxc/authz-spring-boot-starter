package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermMeta;

import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface DataFinderSecurityInterceptor {
    @SuppressWarnings("rawtypes")
    String change(HttpMeta httpMeta, PermLibrary permLibrary, List<DataPermMeta> dataPermMetaList, Class<?> resultType, String sql) throws Exception;
}
