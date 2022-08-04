package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.auth.rpd.Rule;

import java.util.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class RuleParser {

    private RuleParser() {
        throw new UnsupportedOperationException();
    }

    public static String parseRuleToString(Rule rule) {
        String parse = parseRuleToStringNotTrim(rule);
        if (parse.startsWith("(") && parse.endsWith(")")) {return parse.substring(2, parse.length() - 2);} else {
            return parse;
        }
    }

    private static String parseRuleToStringNotTrim(Rule rule) {
        if (rule == null) return "";
        String op = rule.getOp();
        if (op.equals("AND") || op.equals("OR")) {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("( ");
            Iterator<Rule> iterator = rule.getRules().iterator();
            while (iterator.hasNext()) {
                stringBuilder.append(parseRuleToStringNotTrim(iterator.next()));
                if (iterator.hasNext()) {
                    stringBuilder.append(" ").append(op).append(" ");
                } else {
                    stringBuilder.append(" ");
                }
            }
            stringBuilder.append(")");
            return stringBuilder.toString();
        } else {
            return rule.valueShow();
        }
    }

    public static Rule parseStringToRule(String rule) {
        Stack<String>         stack = new Stack<>();
        char[]                chars = rule.toCharArray();
        int                   start = 0;
        HashMap<String, Rule> km    = new HashMap<>();
        int                   n     = 1;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == '(') {
                stack.push(String.valueOf(chars, start, i - start).trim());
                stack.push("(");
                start = i + 1;
            } else if (chars[i] == ')') {
                stack.push(String.valueOf(chars, start, i - start).trim());
                StringBuilder sb = new StringBuilder();
                String        p  = stack.pop();
                while (!p.equals("(")) {
                    sb.insert(0, " ").insert(0, p).insert(0, " ");
                    p = stack.pop();
                }
                Rule to = to(km, sb, n);
                if (to == null) {
                    stack.push(stack.pop() + "(" + sb.substring(1, sb.length() - 1) + ")");
                } else {
                    stack.push("@" + n++);
                }
                start = i + 1;
            } else if (i == chars.length - 1) {
                stack.push(String.valueOf(chars, start, i - start + 1).trim());
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String s : stack) sb.append(" ").append(s).append(" ");
        return to(km, sb, n);
    }

    private static Rule to(Map<String, Rule> map,
                           StringBuilder info,
                           int n) {
        String[] or = info.toString().split(" [oO][rR] ");
        or = Arrays.stream(or).map(String::trim).toArray(String[]::new);
        Rule rr = new Rule();
        if (or.length >= 2) {
            rr.setOp("or");
            ArrayList<Rule> rrules = new ArrayList<>();
            for (String s : or) {
                String[] and = s.split(" [aA][nN][dD] ");
                and = Arrays.stream(and).map(String::trim).toArray(String[]::new);
                if (and.length >= 2) {
                    Rule            r     = new Rule().setOp("and");
                    ArrayList<Rule> rules = new ArrayList<>();
                    for (String v : and) {
                        if (v.startsWith("@")) {
                            rules.add(map.get(v));
                        } else {
                            Rule of = Rule.of(v);
                            if (of != null) rules.add(of);
                        }
                    }
                    r.setRules(rules);
                    rrules.add(r);
                } else {
                    if (and[0].startsWith("@")) {
                        rrules.add(map.get(and[0]));
                    } else {
                        Rule of = Rule.of(and[0]);
                        if (of != null) rrules.add(of);
                    }
                }
            }
            rr.setRules(rrules);
        } else {
            rr.setOp("and");
            String[] and = or[0].split(" [aA][nN][dD] ");
            and = Arrays.stream(and).map(String::trim).toArray(String[]::new);
            if (and.length >= 2) {
                rr.setOp("and");
                ArrayList<Rule> rules = new ArrayList<>();
                for (String v : and) {
                    if (v.startsWith("@")) {
                        rules.add(map.get(v));
                    } else {
                        Rule of = Rule.of(v);
                        if (of != null) rules.add(of);
                    }
                }
                rr.setRules(rules);
            } else {
                if (and[0].startsWith("@")) {
                    rr = map.get(and[0]);
                } else {
                    rr = Rule.of(and[0]);
                }
            }
        }
        String key = "@" + n;
        if (rr != null) map.put(key, rr);
        return rr;
    }

}
