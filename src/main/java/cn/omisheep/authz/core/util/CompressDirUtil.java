package cn.omisheep.authz.core.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.3
 */
public class CompressDirUtil {

    private CompressDirUtil() {
        throw new UnsupportedOperationException();
    }

    public static boolean compressFileToZip(String compresspath) {
        boolean bool = false;
        try {
            ZipOutputStream zipOutput;
            File            file = new File(compresspath);
            if (file.isDirectory()) {
                zipOutput = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(compresspath + ".zip")));
                compressZip(zipOutput, file, "");
            } else {
                zipOutput = new ZipOutputStream(new BufferedOutputStream(
                        new FileOutputStream(compresspath.substring(0, compresspath.lastIndexOf(".")) + ".zip")));
                zipOFile(zipOutput, file);
            }
            zipOutput.closeEntry();
            zipOutput.close();
            bool = true;
        } catch (Exception e) {
            LogUtils.error(e);
        }
        return bool;
    }

    private static void compressZip(ZipOutputStream zipOutput,
                                    File file,
                                    String suffixpath) {
        File[] listFiles = file.listFiles();
        if (listFiles == null) return;
        for (File fi : listFiles) {
            if (fi.isDirectory()) {
                if (suffixpath.equals("")) {
                    compressZip(zipOutput, fi, fi.getName());
                } else {
                    compressZip(zipOutput, fi, suffixpath + File.separator + fi.getName());
                }
            } else {
                zip(zipOutput, fi, suffixpath);
            }
        }
    }

    public static void zip(ZipOutputStream zipOutput,
                           File file,
                           String suffixpath) {
        try {
            ZipEntry zEntry = null;
            if (suffixpath.equals("")) {
                zEntry = new ZipEntry(file.getName());
            } else {
                zEntry = new ZipEntry(suffixpath + File.separator + file.getName());
            }
            zipOutput.putNextEntry(zEntry);
            BufferedInputStream bis    = new BufferedInputStream(new FileInputStream(file));
            byte[]              buffer = new byte[1024];
            int                 read   = 0;
            while ((read = bis.read(buffer)) != -1) {
                zipOutput.write(buffer, 0, read);
            }
            bis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void zipOFile(ZipOutputStream zipOutput,
                                File file) {
        try {
            ZipEntry zEntry = new ZipEntry(file.getName());
            zipOutput.putNextEntry(zEntry);
            BufferedInputStream bis    = new BufferedInputStream(new FileInputStream(file));
            byte[]              buffer = new byte[1024];
            int                 read   = 0;
            while ((read = bis.read(buffer)) != -1) {
                zipOutput.write(buffer, 0, read);
            }
            bis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}