package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.util.RuleParser;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataPermRolesMeta extends PermRolesMeta {

    private String                    condition;
    private Rule                      rule;
    private Map<String, List<String>> argsMap;

    public static DataPermRolesMeta of(String condition) {
        return new DataPermRolesMeta().setRule(RuleParser.parseStringToRule(condition)).setCondition(condition);
    }

    public static DataPermRolesMeta of(Rule rule) {
        return new DataPermRolesMeta().setCondition(RuleParser.parseRuleToString(rule)).setRule(rule);
    }

    public DataPermRolesMeta addArg(String source,
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
