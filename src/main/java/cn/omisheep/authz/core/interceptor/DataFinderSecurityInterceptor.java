package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.FieldDataPermRolesMeta;

import java.util.List;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("rawtypes")
public interface DataFinderSecurityInterceptor {
    String sqlChange(HttpMeta httpMeta,
                     List<DataPermRolesMeta> dataPermRolesMetaList,
                     Class<?> resultType,
                     String sql) throws Exception;

    Object dataTrim(HttpMeta httpMeta,
                    Map<String, FieldDataPermRolesMeta> fieldDataMap,
                    Class<?> resultType,
                    Object obj);
}
