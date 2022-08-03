package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermMeta;
import cn.omisheep.authz.core.auth.rpd.FieldData;
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
                            List<DataPermMeta> dataPermMetaList,
                            Class<?> resultType,
                            String sql) throws JSQLParserException {
        if (dataPermMetaList.size() == 0) return sql;

        Set<String> rolesByUserId     = httpMeta.getRoles();
        Set<String> permissionsByRole = httpMeta.getPermissions();

        Iterator<String> iterator = dataPermMetaList.stream().filter(dataPermMeta -> {
            Meta roles = dataPermMeta.getRoles();
            if (roles != null) {
                return CollectionUtils.containsSub(roles.getRequire(), rolesByUserId);
            } else {
                Meta permissions = dataPermMeta.getPermissions();
                if (permissions == null) return false;
                return CollectionUtils.containsSub(permissions.getRequire(), permissionsByRole);
            }
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
        ;

        Expression securityWhere = CCJSqlParserUtil.parseCondExpression(sb.toString());

        return selectBody.withWhere(securityWhere).toString();
    }

    @Override
    public Object dataTrim(HttpMeta httpMeta,
                           PermLibrary permLibrary,
                           Map<String, FieldData> fieldDataMap,
                           Class<?> resultType,
                           Object obj) {
        try {
            Set<String> rolesByUserId     = httpMeta.getRoles();
            Set<String> permissionsByRole = httpMeta.getPermissions();

            ArrayList<String> deleted = new ArrayList<>();

            fieldDataMap.forEach((k, v) -> {
                Meta r = v.getRoles();
                Meta p = v.getPermissions();
                if ((r != null && r.getRequire() != null && !CollectionUtils.containsSub(r.getRequire(), rolesByUserId))
                        || (p != null && p.getRequire() != null && !CollectionUtils.containsSub(p.getRequire(),
                                                                                                permissionsByRole))
                        || (r != null && r.getExclude() != null && CollectionUtils.containsSub(r.getExclude(),
                                                                                               rolesByUserId))
                        || (p != null && p.getExclude() != null && CollectionUtils.containsSub(p.getExclude(),
                                                                                               permissionsByRole))
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
