package cn.omisheep.authz.support.util;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public abstract class SupportUtils {

    public final static int DEFAULT_BUFFER_SIZE = 1024 * 4;

    public static String read(InputStream in) {
        InputStreamReader reader;
        reader = new InputStreamReader(in, StandardCharsets.UTF_8);
        return read(reader);
    }

    public static String readFromResource(String resource) {
        InputStream in = null;
        try {
            in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
            if (in == null) {
                in = SupportUtils.class.getResourceAsStream(resource);
            }

            if (in == null) {
                return null;
            }

            return SupportUtils.read(in);
        } finally {
            close(in);
        }
    }

    public static String read(Reader reader) {
        try {

            StringWriter writer = new StringWriter();

            char[] buffer = new char[DEFAULT_BUFFER_SIZE];
            int    n;
            while (-1 != (n = reader.read(buffer))) {
                writer.write(buffer, 0, n);
            }

            return writer.toString();
        } catch (IOException ex) {
            throw new IllegalStateException("read error", ex);
        }
    }

    public static byte[] readByteArrayFromResource(String resource) throws IOException {
        InputStream in = null;
        try {
            in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
            if (in == null) {
                return null;
            }

            return readByteArray(in);
        } finally {
            close(in);
        }
    }

    public static byte[] readByteArray(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        copy(input, output);
        return output.toByteArray();
    }

    public static void copy(InputStream input, OutputStream output) throws IOException {
        final int EOF = -1;

        byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];

        int n;
        while (EOF != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
        }
    }

    public static void close(Closeable x) {
        if (x == null) {
            return;
        }
        try {
            x.close();
        } catch (Exception e) {
            log.debug("close error", e);
        }
    }
}
