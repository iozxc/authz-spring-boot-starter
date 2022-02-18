package cn.omisheep.authz.core.handler;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class BufferedServletRequestWrapper extends HttpServletRequestWrapper {
    private final byte[] buffer;

    public BufferedServletRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        InputStream is = request.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buff = new byte[1024];
        int read;
        while ((read = is.read(buff)) > 0) {
            baos.write(buff, 0, read);
        }
        this.buffer = baos.toByteArray();
    }

    @Override
    public ServletInputStream getInputStream() {
        return new BufferedServletInputStream(this.buffer);
    }

    /**
     * HttpServletRequest
     */
    public static class BufferedServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream inputStream;

        public BufferedServletInputStream(byte[] buffer) {
            this.inputStream = new ByteArrayInputStream(buffer);
        }

        @Override
        public int available() {
            return inputStream.available();
        }

        @Override
        public int read() {
            return inputStream.read();
        }

        @Override
        public int read(byte[] b, int off, int len) {
            return inputStream.read(b, off, len);
        }

        @Override
        public boolean isFinished() {
            return false;
        }

        @Override
        public boolean isReady() {
            return false;
        }

        @Override
        public void setReadListener(ReadListener readListener) {

        }
    }
}