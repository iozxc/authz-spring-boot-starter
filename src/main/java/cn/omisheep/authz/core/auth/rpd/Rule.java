package cn.omisheep.authz.core.auth.rpd;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.ToString;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <pre>
 *         // id={userID} or ( {userId} in {销售经理Id} and (amount > 100000 or amount < 4000) )
 *         //    rule1               rule2                     rule3               rule4
 *         Rule rule1 = new Rule().setField("id").setOp("eq").setValue("#{userId}");
 *         Rule rule2 = new Rule().setField("userId").setOp("in").setValue("#{销售经理.id}");
 *         Rule rule3 = new Rule().setField("amount").setOp(">").setValue("10000");
 *         Rule rule4 = new Rule().setField("amount").setOp("<").setValue("4000");
 *         Rule rule = Rule.or(rule1, Rule.and(rule2, Rule.or(rule3, rule4)));
 * </pre>
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Rule {

    @Getter
    private List<Rule> rules;
    @Getter
    private String     field;
    private Op         op;
    @Getter
    private String     value;

    public String getOp() {
        if (op == null) return null;
        return op.keyword;
    }

    public Rule setOp(String op) {
        if (op == null) return this;
        if (op.equals("")) return this;
        String s = op.trim().toUpperCase(Locale.ROOT);
        try {
            this.op = Op.valueOf(s);
        } catch (Exception e) {
            for (Op v : Op.values()) {
                if (v.keyword.equals(s)) {
                    this.op = v;
                    break;
                }
            }
        }
        return this;
    }

    enum Op {
        AND("AND"),
        OR("OR"),
        NOT_LIKE("NOT IN"),
        IN("IN"),
        NOT_IN("NOT LIKE"),
        LIKE("LIKE"),
        EQ("="),
        NE("!="),
        LE("<="),
        LT("<"),
        GE(">="),
        GT(">");

        Op(String keyword) {
            this.keyword = keyword;
        }

        private final String keyword;

        public String getKeyword() {
            return keyword;
        }
    }

    private static final Pattern compile =
            Pattern.compile("(.*?)(=|!=|<=|<|>=|>|[nN][oO][tT] *?[iI][nN]|[iI][nN]|[nN][oO][tT] *?[lL][iL][kK][eE]|[lL][iI][kK][eE])(.*)");

    public static Rule of(String info) {
        Matcher matcher = compile.matcher(info);
        if (matcher.find()) {
            return new Rule().setField(matcher.group(1)).setOp(matcher.group(2)).setValue(matcher.group(3));
        }
        return null;
    }

    public static Rule or(Rule rule1, Rule rule2) {
        return new Rule().setOp("or").setRules(Arrays.asList(rule1, rule2));
    }

    public static Rule and(Rule... rules) {
        return new Rule().setOp("and").setRules(Arrays.asList(rules));
    }

    public Rule setRules(List<Rule> rules) {
        this.rules = rules;
        return this;
    }

    public Rule setField(String field) {
        if (field != null) field = field.trim();
        this.field = field;
        return this;
    }

    public Rule setValue(String value) {
        if (value != null) value = value.trim();
        this.value = value;
        return this;
    }

    public String valueShow() {
        return field + " " + op.keyword + " " + value;
    }
}
