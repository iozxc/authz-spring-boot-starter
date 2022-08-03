package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.FieldDataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.Meta;
import cn.omisheep.authz.core.util.ArgsParser;
import cn.omisheep.commons.util.CollectionUtils;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.expression.Expression;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.Select;

import java.lang.reflect.Field;
import java.util.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class DefaultDataSecurityInterceptor implements DataFinderSecurityInterceptor {

    @Override
    public String sqlChange(HttpMeta httpMeta,
                            PermLibrary permLibrary,
                            List<DataPermRolesMeta> dataPermRolesMetaList,
                            Class<?> resultType,
                            String sql) throws JSQLParserException {
        if (dataPermRolesMetaList.size() == 0) return sql;

        Set<String> rolesByUserId     = httpMeta.getRoles();
        Set<String> permissionsByRole = httpMeta.getPermissions();

        Iterator<String> iterator = dataPermRolesMetaList.stream().filter(dataPermMeta -> {
            boolean          flag         = false;
            Set<Set<String>> requireRoles = dataPermMeta.getRequireRoles();
            if (requireRoles != null) {
                flag = flag || CollectionUtils.containsSub(requireRoles, rolesByUserId);
            }
            Set<Set<String>> excludeRoles = dataPermMeta.getExcludeRoles();
            if (requireRoles != null) {
                flag = flag || !CollectionUtils.containsSub(excludeRoles, rolesByUserId);
            }
            Set<Set<String>> requirePermissions = dataPermMeta.getRequirePermissions();
            if (requirePermissions != null) {
                flag = flag || CollectionUtils.containsSub(requirePermissions, permissionsByRole);
            }
            Set<Set<String>> excludePermissions = dataPermMeta.getExcludePermissions();
            if (requireRoles != null) {
                flag = flag || !CollectionUtils.containsSub(excludePermissions, permissionsByRole);
            }
            return flag;
        }).map(d -> {
            return ArgsParser.parse(d);
        }).iterator();

        if (!iterator.hasNext()) return sql;

        Select      select     = (Select) CCJSqlParserUtil.parse(sql);
        PlainSelect selectBody = (PlainSelect) select.getSelectBody();
        Expression  where      = selectBody.getWhere();

        StringBuilder sb = new StringBuilder();
        sb.append(" ( ");
        while (iterator.hasNext()) {
            sb.append(iterator.next());
            if (iterator.hasNext()) {sb.append(" OR ");} else {
                if (where != null) {sb.append(" ) AND ").append(where);} else sb.append(" ) ");
            }
        }

        Expression securityWhere = CCJSqlParserUtil.parseCondExpression(sb.toString());

        return selectBody.withWhere(securityWhere).toString();
    }

    @Override
    public Object dataTrim(HttpMeta httpMeta,
                           PermLibrary permLibrary,
                           Map<String, FieldDataPermRolesMeta> fieldDataMap,
                           Class<?> resultType,
                           Object obj) {
        try {
            Set<String> rolesByUserId     = httpMeta.getRoles();
            Set<String> permissionsByRole = httpMeta.getPermissions();

            ArrayList<String> deleted = new ArrayList<>();

            fieldDataMap.forEach((k, v) -> {
                Meta r = v.getRoles();
                Meta p = v.getPermissions();
                if ((!CollectionUtils.containsSub(r.getRequire(), rolesByUserId))
                        || (!CollectionUtils.containsSub(p.getRequire(), permissionsByRole))
                        || (CollectionUtils.containsSub(r.getExclude(), rolesByUserId))
                        || (CollectionUtils.containsSub(p.getExclude(), permissionsByRole))
                ) {
                    deleted.add(k);//任意一个没有满足则从字段中删除
                }
            });

            if (obj instanceof Collection) {
                ((Collection) obj).forEach(o -> {
                    for (String d : deleted) {
                        try {
                            Field declaredField = resultType.getDeclaredField(d);
                            declaredField.setAccessible(true);
                            declaredField.set(o, null);
                        } catch (Exception e) {
                        }
                    }
                });
            }

            return obj;
        } catch (Exception e) {
            return obj;
        }
    }

}
