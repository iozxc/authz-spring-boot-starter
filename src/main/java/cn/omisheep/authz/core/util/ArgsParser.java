package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.auth.rpd.ArgsHandler;
import cn.omisheep.authz.core.auth.rpd.DataPermRolesMeta;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 类似与SpelExpressionParser，但是不同，此类只解析参数 如#{}和${}，同时支持#{token.userId}获取其中属性的用法。
 * 支持 数组.字段名、 数组.数组 (list.list)
 * 结构参考json
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public abstract class ArgsParser {


    private static final Pattern c = Pattern.compile("[#$]?\\{(.*?)}");

    public static Object parse(String argName) {
        return parse(argName, null);
    }

    public static <E> Object parse(String argName,
                                   Supplier<E> fail) {
        Matcher matcher = c.matcher(argName);
        if (!matcher.find()) {
            if (fail == null) {return argName;} else return fail.get();
        }
        String   obj     = matcher.group(1);
        String[] trace   = obj.split("\\.");
        Object   convert = convert(trace, ArgsHandler.handle(trace[0]));
        if (isArrayOrCollection(convert)) {
            String arrString = parseAndToString(convert);
            if (arrString == null) return argName;
            return Arrays.stream(arrString.substring(1, arrString.length() - 1).trim().split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
        } else {
            return convert;
        }
    }

    public static String parse(DataPermRolesMeta dataPermRolesMeta) {
        StringBuilder stringBuilder = new StringBuilder();
        String        condition     = dataPermRolesMeta.getCondition();
        int           index         = 0;
        int           i             = 0;
        char          op            = '#';
        while (index != -1) {
            if (i % 2 == 0) {
                int k = condition.indexOf("{", index);
                if (k != -1) {
                    char o;
                    if (k - 1 < 0) {
                        o = '#';
                    } else {o = condition.charAt(k - 1);}
                    if (o == '#' || o == '$') {
                        op = o;
                        stringBuilder.append(condition, index, k - 1);
                    } else {
                        stringBuilder.append(condition, index, k);
                    }
                    index = k;
                } else {
                    if (condition.indexOf("}", index) != -1) {
                        return null;
                    } else {
                        if (stringBuilder.length() == 0) return condition;
                        return reduce(stringBuilder.append(condition, index, condition.length()).toString());
                    }
                }
            } else {
                int k = condition.indexOf("}", index);
                if (k != -1) {
                    String   item  = condition.substring(index + 1, k);
                    String[] trace = item.split("\\.");
                    stringBuilder.append(parseObject(op, trace, ref(trace[0], dataPermRolesMeta)));
                    index = k + 1;
                } else {
                    return null;
                }
            }
            i++;
        }
        return null;
    }

    private static String reduce(String s) {
        char[]        chars   = s.toCharArray();
        StringBuilder builder = new StringBuilder();
        int           is      = 0;
        boolean       in      = false;
        for (int i = 0; i < chars.length; i++) {
            if (i + 2 < chars.length) {
                if (s.substring(i, i + 2).equalsIgnoreCase("in")) {
                    in = true;
                }
            }
            if (in) {
                if (chars[i] == '(') {
                    is++;
                    if (is > 1) continue;
                } else if (chars[i] == ')') {
                    is--;
                    if (is != 0) continue;
                    in = false;
                }
            }
            builder.append(chars[i]);
        }
        return builder.toString();
    }

    private static Object ref(String argName,
                              DataPermRolesMeta dataPermRolesMeta) {
        Map<String, List<String>> argsMap = dataPermRolesMeta.getArgsMap();
        if (argsMap == null) return argsHandle(argName);
        List<String> list = dataPermRolesMeta.getArgsMap().get(argName);
        if (list == null || list.isEmpty()) return argsHandle(argName);
        ArrayList<Object> argsList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            Matcher matcher = c.matcher(list.get(i));
            if (matcher.find()) {
                argsList.add(ref(matcher.group(1), dataPermRolesMeta));
            } else {
                List<Class<?>> paramType = ArgsHandler.argType(argName);
                if (paramType == null) {
                    throw new RuntimeException("参数个数不匹配");
                }
                Class<?> aClass = paramType.get(i);
                try {
                    argsList.add(aClass.getConstructor(String.class).newInstance(list.get(i)));
                } catch (InstantiationException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                    LogUtils.error(e);
                }
            }
        }
        return argsHandle(argName, argsList.toArray());
    }

    private static String parseObject(char op,
                                      String[] trace,
                                      Object value) {
        if (op == '#') {
            if (value == null) return "";
            Object convert = convert(trace, value);
            if (isArrayOrCollection(convert)) {
                return parseAndToString(convert);
            }
            return convert.toString();
        } else if (op == '$') {
            return parseObject('#', trace, value);
        } else {
            return parseObject('#', trace, value);
        }
    }

    private static Object argsHandle(String argName,
                                     Object... otherArgs) {
        return ArgsHandler.handle(argName, otherArgs);
    }

    private static final Pattern compile = Pattern.compile("(.*?)\\[(\\d+|\\*)]");

    private static Object convert(String[] trace,
                                  Object obj) {
        if (trace.length == 1) {
            return obj;
        } else {
            Object     value;
            Object     json = JSON.toJSON(obj);
            JSONObject o    = null;
            JSONArray  a    = null;
            boolean    isObject;
            if (json instanceof JSONObject) {
                isObject = true;
                o        = (JSONObject) json;
            } else {
                isObject = false;
                a        = (JSONArray) json;
            }
            for (int i = 1; i < trace.length - 1; i++) {
                Matcher matcher = compile.matcher(trace[i]);
                if (matcher.find()) {
                    if (matcher.group(2).equals("*")) {
                        if (isObject) {
                            a = o.getJSONArray(matcher.group(1));
                        } else {
                            a = new JSONArray(collect(a, matcher.group(1)));
                        }
                        isObject = false;
                    } else {
                        int ii = Integer.parseInt(matcher.group(2));
                        if (isObject) {
                            o = (JSONObject) o.getJSONArray(matcher.group(1)).get(ii);
                        } else {
                            a = new JSONArray(collect(a, matcher.group(1), ii));
                        }
                    }
                } else {
                    if (isObject) {
                        Object o1 = o.get(trace[i]);
                        if (o1 instanceof JSONObject) {o = (JSONObject) o1;} else {
                            a        = (JSONArray) o1;
                            isObject = false;
                        }
                    } else {
                        a = new JSONArray(collect(a, trace[i]));
                    }

                }
            }

            String  v       = trace[trace.length - 1];
            Matcher matcher = compile.matcher(v);
            if (!isObject) {
                if (matcher.find()) {
                    if (matcher.group(2).equals("*")) {
                        return collect(a, matcher.group(1));
                    } else {
                        return collect(a, matcher.group(1), Integer.parseInt(matcher.group(2)));
                    }
                } else {
                    return collect(a, v);
                }
            } else {
                if (matcher.find()) {
                    if (matcher.group(2).equals("*")) {
                        value = o.getJSONArray(matcher.group(1));
                    } else {
                        value = o.getJSONArray(matcher.group(1)).get(Integer.parseInt(matcher.group(2)));
                    }
                } else {
                    value = o.get(v);
                }
                return value;
            }
        }
    }

    private static List<Object> collect(List<Object> a,
                                        String name,
                                        int i) {
        return (List<Object>) a.stream().flatMap(jo -> {
            if (jo == null) return null;
            if (jo instanceof JSONObject) {
                return Stream.of(((JSONObject) jo).getJSONArray(name).get(i));
            } else {
                return ((JSONArray) jo).stream()
                        .map(jox -> ((JSONObject) jox).getJSONArray(name).get(i));
            }
        }).collect(Collectors.toList());
    }

    private static List<Object> collect(List<Object> a,
                                        String name) {
        return (List<Object>) a.stream().flatMap(jo -> {
            if (jo == null) return null;
            if (jo instanceof JSONObject) {
                return Stream.of(((JSONObject) jo).get(name));
            } else {
                return ((JSONArray) jo).stream()
                        .map(jox -> ((JSONObject) jox).get(name));
            }
        }).collect(Collectors.toList());
    }

    private static boolean isArrayOrCollection(Object o) {
        if (o == null) return false;
        return (o instanceof Collection) || o.getClass().isArray();
    }

    @SuppressWarnings("rawtypes")
    private static String parseAndToString(Object o) {
        if (!isArrayOrCollection(o)) return null;
        if (o.getClass().isArray()) {
            if (o instanceof int[]) {
                return parseArray((int[]) o);
            } else if (o instanceof long[]) {
                return parseArray((long[]) o);
            } else if (o instanceof float[]) {
                return parseArray((float[]) o);
            } else if (o instanceof double[]) {
                return parseArray((double[]) o);
            } else if (o instanceof char[]) {
                return parseArray((char[]) o);
            } else if (o instanceof boolean[]) {
                return parseArray((boolean[]) o);
            } else if (o instanceof short[]) {
                return parseArray((short[]) o);
            } else if (o instanceof String[]) {
                return parseArray((String[]) o);
            } else {return parseArray((Object[]) o);}
        }
        if (o instanceof Collection) return parseArray((Collection) o);
        return null;
    }

    private static String parseArray(short[] a) {
        if (a == null) {return null;}
        int iMax = a.length - 1;
        if (iMax == -1) {return null;}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(int[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(long[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(float[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(double[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(char[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(boolean[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(String[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(Object[] a) {
        if (a == null) {return "";}
        int iMax = a.length - 1;
        if (iMax == -1) {return "";}

        StringBuilder b = new StringBuilder();
        b.append("( ");
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax) {return b.append(" )").toString();}
            b.append(", ");
        }
    }

    private static String parseArray(Collection<?> collection) {
        if (collection == null) {return "";}

        Iterator<?> iterator = collection.iterator();
        if (!iterator.hasNext()) {
            return "";
        }

        StringBuilder b = new StringBuilder();
        b.append("( ");
        while (iterator.hasNext()) {
            Object next = iterator.next();
            if (next instanceof String || next instanceof Character || next.equals(Character.TYPE)) {
                b.append("'").append(next).append("'");
            } else {b.append(next);}
            if (iterator.hasNext()) {b.append(", ");} else b.append(")");
        }

        return b.toString();
    }

}
