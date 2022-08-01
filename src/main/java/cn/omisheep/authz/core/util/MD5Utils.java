package cn.omisheep.authz.core.util;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.3
 */
public class MD5Utils {

    public static String compute(String path) {
        try {
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(path));
            return DigestUtils.md5Hex(bufferedInputStream);
        } catch (IOException e) {
            try {
                boolean b = CompressDirUtil.compressFileToZip(path);
                if (!b) {return "";} else {
                    String zip = path + ".zip";
                    String md5 = DigestUtils.md5Hex(new BufferedInputStream(new FileInputStream(zip)));
                    new File(zip).delete();
                    return md5;
                }
            } catch (Exception ee) {
                return "";
            }
        }
    }

}
