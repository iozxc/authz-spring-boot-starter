package cn.omisheep.authz.core.interceptor.mybatis;

import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.auth.rpd.DataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.FieldDataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.library.L2RefreshCacheSupport;
import cn.omisheep.authz.core.interceptor.DataFinderSecurityInterceptor;
import cn.omisheep.authz.core.util.LogUtils;
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

    private final ThreadLocal<ResultMap>        resultMapThreadLocal = ThreadLocal.withInitial(() -> null);
    private final DataFinderSecurityInterceptor dataFinderSecurityInterceptor;


    public DataSecurityInterceptorForMybatis(DataFinderSecurityInterceptor dataFinderSecurityInterceptor) {
        this.dataFinderSecurityInterceptor = dataFinderSecurityInterceptor;
    }

    public Object intercept(Invocation invocation) throws Throwable {
        if (L2RefreshCacheSupport.isLibrary()) return invocation.proceed();
        Object   target = invocation.getTarget();
        Object[] args   = invocation.getArgs();
        if (target instanceof Executor) {
            MappedStatement ms        = (MappedStatement) args[0];
            ResultMap       resultMap = ms.getResultMaps().get(0);
            resultMapThreadLocal.set(resultMap);
        } else {
            try {
                ResultMap resultMap = resultMapThreadLocal.get();
                if (resultMap == null) return invocation.proceed();
                StatementHandler rsh      = (StatementHandler) target;
                BoundSql         boundSql = rsh.getBoundSql();
                Class<?>         type     = resultMap.getType();
                if (PermissionDict.getDataPermission() == null) return invocation.proceed();
                List<DataPermRolesMeta> dataPermRolesMetaList = PermissionDict.getDataPermission()
                        .get(type.getTypeName());
                String change = dataFinderSecurityInterceptor.sqlChange(AuthzContext.getCurrentHttpMeta(),
                                                                        dataPermRolesMetaList, type, boundSql.getSql());
                System.out.println(change);
                ReflectUtils.setFieldValue(boundSql, "sql", change);
            } catch (Exception e) {
                LogUtils.error(e);
                return invocation.proceed();
            }
        }
        Object obj = invocation.proceed();
        if (PermissionDict.getFieldsData() == null || obj == null) return obj;
        try {
            if (resultMapThreadLocal.get() != null) {
                Class<?> type = resultMapThreadLocal.get().getType();
                if (type.equals(obj.getClass()) || obj instanceof Collection) {
                    if (obj instanceof Collection) {
                        if (((Collection) obj).size() == 0) {
                            return obj;
                        }
                    }
                    Map<String, FieldDataPermRolesMeta> fieldDataMap = PermissionDict.getFieldsData()
                            .get(type.getTypeName());
                    obj = dataFinderSecurityInterceptor.dataTrim(AuthzContext.getCurrentHttpMeta(),
                                                                 fieldDataMap,
                                                                 type, obj);
                    return obj;
                }
            }
        } catch (Exception e) {
            LogUtils.error(e);
        }
        return obj;
    }

}