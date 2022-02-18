package cn.omisheep.authz.core.util;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.RequiredTypeException;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Slf4j
public class Utils {

    /**
     * stirngmatchlen from redis6.x.x/src/util/stringmatchlen
     *
     * @param pattern pattern
     * @param string  string
     * @param nocase  是否忽略大小写
     * @return 匹配
     */
    public static boolean stringMatch(String pattern, String string, boolean nocase) {
        char[] patternChars = pattern.toCharArray();
        char[] stringChars = string.toCharArray();
        return stringMatchLen(0, patternChars, 0, stringChars, nocase);
    }

    private static boolean stringMatchLen(int pIndex, final char[] pattern,
                                          int sIndex, final char[] string,
                                          boolean noCase) {

        while (pattern.length - pIndex > 0 && string.length - sIndex > 0) {
            switch (pattern[pIndex]) {
                case '*':
                    while (pattern.length - pIndex > 0
                            && pIndex + 1 < pattern.length && pattern[pIndex + 1] == '*') {
                        pIndex++;
                    }
                    if (pattern.length - pIndex == 1)
                        return true; /* match */
                    while (string.length - sIndex > 0) {
                        if (stringMatchLen(pIndex + 1, pattern,
                                sIndex, string, noCase))
                            return true; /* match */
                        sIndex++;
                    }
                    return false; /* no match */
                case '?':
                    sIndex++;
                    break;
                case '[': {
                    boolean not, match;

                    pIndex++;
                    not = pattern[pIndex] == '^';
                    if (not) {
                        pIndex++;
                    }
                    match = false;
                    while (true) {
                        if (pattern[pIndex] == '\\' && pattern.length - pIndex >= 2) {
                            pIndex++;
                            if (pattern[pIndex] == string[sIndex])
                                match = true;
                        } else if (pattern[pIndex] == ']') {
                            break;
                        } else if (pattern.length - pIndex >= 3
                                && pIndex + 1 < pattern.length && pattern[pIndex + 1] == '-') {
                            int start = pattern[pIndex];
                            int end = pIndex + 2 < pattern.length ? pattern[pIndex + 2] : 0;
                            int c = string[sIndex];
                            if (start > end) {
                                int t = start;
                                start = end;
                                end = t;
                            }
                            if (noCase) {
                                start = Character.toLowerCase(start);
                                end = Character.toLowerCase(end);
                                c = Character.toLowerCase(c);
                            }
                            pIndex += 2;
                            if (c >= start && c <= end)
                                match = true;
                        } else {
                            if (!noCase) {
                                if (pattern[pIndex] == string[sIndex])
                                    match = true;
                            } else {
                                if (Character.toLowerCase(pattern[pIndex])
                                        == Character.toLowerCase(string[sIndex]))
                                    match = true;
                            }
                        }
                        pIndex++;
                    }
                    if (not)
                        match = !match;
                    if (!match)
                        return false; /* no match */
                    sIndex++;
                    break;
                }
                case '\\':
                    if (pattern.length - pIndex >= 2) {
                        pIndex++;
                    }
                    /* fall through */
                default:
                    if (!noCase) {
                        if (pattern[pIndex] != string[sIndex])
                            return false; /* no match */
                    } else {
                        if (Character.toLowerCase(pattern[pIndex])
                                != Character.toLowerCase(string[sIndex]))
                            return false; /* no match */
                    }
                    sIndex++;
                    break;
            }
            pIndex++;
            if (string.length - sIndex == 0) {
                while (pIndex < pattern.length && pattern[pIndex] == '*' && pattern.length - pIndex == 1) {
                    pIndex++;
                }
                break;
            }
        }
        return pattern.length - pIndex == 0 && string.length - sIndex == 0;
    }

    public static String beautifulJson(Object o) {
        try {
            return new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(o);
        } catch (JsonProcessingException e) {
            return JSON.toJSONString(o, true);
        } catch (Exception e) {
            log.error(e.getMessage());
            return "";
        }
    }

    public static <T> T castValue(Object value, Class<T> requiredType) {
        if (value == null) return null;

        if (requiredType == Date.class && value instanceof Long) {
            value = new Date((Long) value);
        }

        if (value instanceof Integer) {
            int intValue = (Integer) value;
            if (requiredType == Long.class) {
                value = (long) intValue;
            } else if (requiredType == Short.class && Short.MIN_VALUE <= intValue && intValue <= Short.MAX_VALUE) {
                value = (short) intValue;
            } else if (requiredType == Byte.class && Byte.MIN_VALUE <= intValue && intValue <= Byte.MAX_VALUE) {
                value = (byte) intValue;
            }
        }

        if (!requiredType.isInstance(value)) {
            throw new RequiredTypeException("Expected value to be of type: " + requiredType + ", but was " + value.getClass());
        }

        return requiredType.cast(value);
    }

}
