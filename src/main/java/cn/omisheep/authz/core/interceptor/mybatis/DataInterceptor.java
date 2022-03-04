package cn.omisheep.authz.core.interceptor.mybatis;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.ReflectUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.statement.RoutingStatementHandler;
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
import java.sql.SQLException;
import java.util.Arrays;


@Intercepts({
        @Signature(method = "prepare", type = StatementHandler.class, args = {Connection.class, Integer.class}), // mybatis 3.4.0+
        @Signature(method = "query", type = Executor.class, args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class})
})
@Slf4j
@SuppressWarnings("all")
public class DataInterceptor implements Interceptor {

    public static final String MYSQL = "mysql";
    public static final String ORACLE = "oracle";
    private final PermissionDict permissionDict;
    private final PermLibrary permLibrary;

    public DataInterceptor(PermissionDict permissionDict, PermLibrary permLibrary) {
        this.permissionDict = permissionDict;
        this.permLibrary = permLibrary;
    }

    @SuppressWarnings("rawtypes")
    protected ThreadLocal<Page> pageThreadLocal = new ThreadLocal<>();

    public Object intercept(Invocation invocation) throws Throwable {
        if (invocation.getTarget() instanceof StatementHandler) { // class: StatementHandler , method: Statement prepare(Connection var1, Integer var2)
            Page page = pageThreadLocal.get();
            System.out.println(page);
            RoutingStatementHandler handler = (RoutingStatementHandler) invocation.getTarget();
            StatementHandler delegate = (StatementHandler) ReflectUtil.getFieldValue(handler, "delegate");
            BoundSql boundSql = delegate.getBoundSql();

            Connection connection = (Connection) invocation.getArgs()[0];
            // 准备数据库类型
            String databaseType = decideDatabaseType(connection);

            MappedStatement mappedStatement = (MappedStatement) ReflectUtil.getFieldValue(delegate, "mappedStatement");
            for (ResultMap resultMap : mappedStatement.getResultMaps()) {
                System.out.println("resultMap" + resultMap.getType());
            }
            System.out.println("getDatabaseId" + mappedStatement.getDatabaseId());
//            System.out.println(permissionDict.getAuthzDataFilterMetadata());
            String sql = boundSql.getSql();
            System.out.println(sql);
            String recombineSql = recombineSql(mappedStatement.getResultMaps().get(0).getType(), sql);
            System.out.println("recombineSql: \n" + recombineSql);
            ReflectUtil.setFieldValue(boundSql, "sql", recombineSql);

            System.out.println(Arrays.toString(mappedStatement.getKeyColumns()));
            String mappedStatementId = mappedStatement.getId();
            String className = mappedStatementId.substring(0, mappedStatementId.lastIndexOf("."));
            System.out.println(className);

        } else if (invocation.getTarget() instanceof Executor) { // class: Executor , method: <E> List<E> query(MappedStatement var1, Object var2, RowBounds var3, ResultHandler var4)
            System.out.println(invocation.getArgs()[1]);
        }
        return invocation.proceed();
    }

    protected String decideDatabaseType(Connection connection) throws SQLException {
        String productName = connection.getMetaData().getDatabaseProductName();
        productName = productName.toLowerCase();
        if (productName.contains(MYSQL)) {
            log.info("自动检测到的数据库类型为: " + MYSQL);
            return MYSQL;
        } else if (productName.contains(ORACLE)) {
            log.info("自动检测到的数据库类型为: " + ORACLE);
            return ORACLE;
        }
        throw new PageNotSupportException();
    }

    protected String recombineSql(Class<?> resultType, String sql) {
//        HttpMeta httpMeta = (HttpMeta) HttpUtils.getCurrentRequest().getAttribute(Constants.HTTP_META);
//        if (httpMeta == null) return sql;

        return sql;
//        Map<String, List<DataPermMeta>> nameAndDataPermMetaMap = permissionDict.getAuthzDataFilterMetadata().get(resultType.getTypeName());
//        Map<String, String> nameAndTypeMap = permissionDict.getAuthzResourcesNameAndTemplate().get(resultType.getTypeName());
//
//        System.out.println(nameAndDataPermMetaMap);
//
//        HashMap<String, Set<String>> belongMap = new HashMap<>();
//        Set<String> roles = null;
//
//        roles = permLibrary.getRolesByUserId(httpMeta.getUserId());
//
//        for (Map.Entry<String, List<DataPermMeta>> entry : nameAndDataPermMetaMap.entrySet()) {
//            for (DataPermMeta dataPermMeta : entry.getValue()) {
//                List<PermRolesMeta.Meta> rolesMetaList = dataPermMeta.getRolesMetaList();
//                for (PermRolesMeta.Meta meta : rolesMetaList) {
//                    if (CollectionUtils.containsSub(meta.getRequire(), roles)) {
//                        Set<String> resources = meta.getResources();
//                        if (resources != null) {
//                            belongMap.computeIfAbsent(entry.getKey(), r -> new HashSet<>()).addAll(resources);
//                        }
//                    }
//                }
//            }
//        }
//
//        StringBuilder whereBuilder = new StringBuilder("where ");
//
//        Iterator<Map.Entry<String, Set<String>>> entryIterator = belongMap.entrySet().iterator();
//        while (entryIterator.hasNext()) {
//            Map.Entry<String, Set<String>> next = entryIterator.next();
//            String type = nameAndTypeMap.get(next.getKey());
//
//            Class<?> valueType = ValueMatcher.getType(type);
//            if (valueType == null) continue;
//            Iterator<String> iterator = next.getValue().iterator();
//            if (iterator.hasNext()) {
//                whereBuilder.append("s.").append(next.getKey());
//                if (valueType.equals(String.class)) {
//                    whereBuilder.append(" in ( ");
//                    while (iterator.hasNext()) {
//                        whereBuilder.append("'").append(iterator.next()).append("'");
//                        if (iterator.hasNext()) whereBuilder.append(", ");
//                        else whereBuilder.append(" )");
//                    }
//                } else if (valueType.equals(Boolean.class)) {
//                    whereBuilder.append(" in ( ");
//                    while (iterator.hasNext()) {
//                        whereBuilder.append(iterator.next());
//                        if (iterator.hasNext()) whereBuilder.append(", ");
//                        else whereBuilder.append(" )");
//                    }
//                }
//            }
//
//            if (entryIterator.hasNext()) {
//                whereBuilder.append(" and ");
//            }
//        }
//
//
//        System.out.println(belongMap);
//        System.out.println(whereBuilder.toString());
//
//        System.out.println(roles);
////        return sql;
//        StringBuilder sbSql = new StringBuilder();
//////        permissionDict.getAuthzDataFilterMetadata().get("")
//        sbSql = new StringBuilder("select * from (")
//                .append(sql)
//                .append(" ) s ")
//                .append(whereBuilder);
//        return sbSql.toString();
    }

}