package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.util.ArgsParser;
import cn.omisheep.commons.util.CollectionUtils;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.expression.Expression;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.Select;

import java.util.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class DefaultDataSecurityInterceptor implements DataFinderSecurityInterceptor {

    @Override
    @SuppressWarnings("all")
    public String change(HttpMeta httpMeta, PermLibrary permLibrary, List<DataPermMeta> dataPermMetaList, Class<?> resultType, String sql) throws JSQLParserException {
        if (dataPermMetaList.size() == 0) return sql;

        Set<String> rolesByUserId = Optional.ofNullable(httpMeta.getRoles()).orElse(permLibrary.getRolesByUserId(httpMeta.getUserId()));
        Set<String> permissionsByRole = Optional.ofNullable(httpMeta.getPermissions()).orElseGet(() -> {
            HashSet<String> perms = new HashSet<>();
            rolesByUserId.forEach(role -> perms.addAll(permLibrary.getPermissionsByRole(role)));
            return perms;
        });

        Iterator<String> iterator = dataPermMetaList.stream().filter(dataPermMeta -> {
            PermRolesMeta.Meta roles = dataPermMeta.getRoles();
            if (roles != null) {
                return CollectionUtils.containsSub(roles.getRequire(), rolesByUserId);
            } else {
                PermRolesMeta.Meta permissions = dataPermMeta.getPermissions();
                if (permissions == null) return false;
                return CollectionUtils.containsSub(permissions.getRequire(), permissionsByRole);
            }
        }).map(d -> {
            return ArgsParser.parse(d);
        }).iterator();

        if (!iterator.hasNext()) return sql;

        StringBuilder sb = new StringBuilder();
        while (iterator.hasNext()) {
            sb.append(iterator.next()).append(" AND ");
        }

        Select select = (Select) CCJSqlParserUtil.parse(sql);
        PlainSelect selectBody = (PlainSelect) select.getSelectBody();
        Expression securityWhere = CCJSqlParserUtil.parseCondExpression(sb.toString() + selectBody.getWhere());

        return selectBody.withWhere(securityWhere).toString();
    }

}
