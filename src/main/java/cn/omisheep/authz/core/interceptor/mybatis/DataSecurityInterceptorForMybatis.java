package cn.omisheep.authz.core.interceptor.mybatis;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.rpd.DataPermMeta;
import cn.omisheep.authz.core.auth.rpd.FieldData;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.interceptor.DataFinderSecurityInterceptor;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.ReflectUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.sql.Connection;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Intercepts({
        @Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class, Integer.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class, CacheKey.class, BoundSql.class})
})
@Slf4j
@SuppressWarnings("all")
public class DataSecurityInterceptorForMybatis implements Interceptor {

    private       ThreadLocal<ResultMap>        resultMapThreadLocal = new ThreadLocal<>();
    private final PermissionDict                permissionDict;
    private final PermLibrary                   permLibrary;
    private final DataFinderSecurityInterceptor dataFinderSecurityInterceptor;

    public DataSecurityInterceptorForMybatis(PermissionDict permissionDict, PermLibrary permLibrary,
                                             DataFinderSecurityInterceptor dataFinderSecurityInterceptor) {
        this.permissionDict                = permissionDict;
        this.permLibrary                   = permLibrary;
        this.dataFinderSecurityInterceptor = dataFinderSecurityInterceptor;
    }

    public Object intercept(Invocation invocation) throws Throwable {
        Object   target = invocation.getTarget();
        Object[] args   = invocation.getArgs();
        if (target instanceof Executor) {
            MappedStatement ms        = (MappedStatement) args[0];
            ResultMap       resultMap = ms.getResultMaps().get(0);
            resultMapThreadLocal.set(resultMap);
        } else {
            try {
                ResultMap          resultMap        = resultMapThreadLocal.get();
                StatementHandler   rsh              = (StatementHandler) target;
                BoundSql           boundSql         = rsh.getBoundSql();
                Class<?>           type             = resultMap.getType();
                List<DataPermMeta> dataPermMetaList = permissionDict.getDataPermission().get(type.getTypeName());
                String             change           = dataFinderSecurityInterceptor.sqlChange(AUtils.getCurrentHttpMeta(), permLibrary, dataPermMetaList, type, boundSql.getSql());
                ReflectUtils.setFieldValue(boundSql, "sql", change);
            } catch (Exception e) {
                e.printStackTrace();
                log.error("sql解析异常或则可能处于非web环境");
                return invocation.proceed();
            }
        }
        Object   obj  = invocation.proceed();
        Class<?> type = resultMapThreadLocal.get().getType();
        if (obj instanceof Collection || obj.getClass().equals(type)) {
            Map<String, FieldData> fieldDataMap = permissionDict.getFieldsData().get(type.getTypeName());
            obj = dataFinderSecurityInterceptor.dataTrim(AUtils.getCurrentHttpMeta(), permLibrary, fieldDataMap, type, obj);
        }

        return obj;
    }

}