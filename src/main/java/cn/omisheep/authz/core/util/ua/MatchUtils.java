package cn.omisheep.authz.core.util.ua;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author zhouxinchen
 * @since 1.2.7
 */
public class MatchUtils {

    private MatchUtils() {
        throw new UnsupportedOperationException();
    }

    public static boolean match(Pattern pattern,
                                String content) {
        if (pattern == null || content == null) {
            return false;
        }
        return pattern.matcher(content).find();
    }

    public static String group(Pattern pattern,
                               String content,
                               int index) {
        if (pattern == null || content == null) {
            return null;
        }
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            try {
                return matcher.group(index);
            } catch (Exception e) {
                return null;
            }
        } else {
            return null;
        }
    }

}
