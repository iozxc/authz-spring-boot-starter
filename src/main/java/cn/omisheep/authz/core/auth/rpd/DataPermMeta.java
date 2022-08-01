package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.util.RuleParser;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataPermMeta {

    private PermRolesMeta.Meta        roles;
    private PermRolesMeta.Meta        permissions;
    private String                    condition;
    private Rule                      rule;
    private Map<String, List<String>> argsMap;

    public static DataPermMeta of(String condition) {
        return new DataPermMeta().setRule(RuleParser.parseStringToRule(condition)).setCondition(condition);
    }

    public static DataPermMeta of(Rule rule) {
        return new DataPermMeta().setCondition(RuleParser.parseRuleToString(rule)).setRule(rule);
    }

    public DataPermMeta addArg(String source,
                               List<String> args) {
        if (argsMap == null) argsMap = new HashMap<>();
        argsMap.put(source, args);
        return this;
    }

    public void addArg(String source,
                       String... args) {
        if (argsMap == null) argsMap = new HashMap<>();
        if (args != null) argsMap.put(source, Arrays.stream(args).collect(Collectors.toList()));
    }

}
