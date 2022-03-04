package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.util.RuleParser;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataPermMeta {

    private PermRolesMeta.Meta roles;
    private PermRolesMeta.Meta permissions;
    private String condition;
    private Rule rule;
    private Map<String, List<String>> argsMap;

    public static DataPermMeta of(String condition) {
        DataPermMeta dataPermMeta = new DataPermMeta();
        dataPermMeta.setRule(RuleParser.parseStringToRule(condition));
        dataPermMeta.setCondition(condition);
        return dataPermMeta;
    }

    public static DataPermMeta of(Rule rule) {
        DataPermMeta dataPermMeta = new DataPermMeta();
        dataPermMeta.setCondition(RuleParser.parseRuleToString(rule));
        dataPermMeta.setRule(rule);
        return dataPermMeta;
    }

    public DataPermMeta addArg(String source, List<String> args) {
        if (argsMap == null) {
            argsMap = new HashMap<>();
        }
        argsMap.put(source, args);
        return this;
    }

    public DataPermMeta addArg(String source, String... args) {
        if (argsMap == null) {
            argsMap = new HashMap<>();
        }
        if (args != null) argsMap.put(source, Arrays.stream(args).collect(Collectors.toList()));
        return this;
    }

}
