package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermMeta;
import cn.omisheep.authz.core.auth.rpd.FieldData;

import java.util.List;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("rawtypes")
public interface DataFinderSecurityInterceptor {
    String sqlChange(HttpMeta httpMeta, PermLibrary permLibrary, List<DataPermMeta> dataPermMetaList, Class<?> resultType, String sql) throws Exception;

    Object dataTrim(HttpMeta httpMeta, PermLibrary permLibrary, Map<String, FieldData> fieldDataMap, Class<?> resultType, Object obj);
}
