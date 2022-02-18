package cn.omisheep.authz.core.handler;


import cn.omisheep.authz.core.auth.AuRsa;
import cn.omisheep.authz.core.util.AUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;

import java.io.*;
import java.util.stream.Collectors;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class DecryptRequestBodyHandler implements HttpInputMessage {

    private final HttpHeaders headers;
    private final InputStream body;

    public DecryptRequestBodyHandler(HttpInputMessage inputMessage, String privateKey) throws IOException {

        this.headers = inputMessage.getHeaders();
        String content = new BufferedReader(new InputStreamReader(inputMessage.getBody()))
                .lines().collect(Collectors.joining(System.lineSeparator()));

        // 将原本的json整个加密，然后再放到一个空对象中，请勿直接传递加密的数据
        String decrypt = AuRsa.decrypt(AUtils.parse_RSA_JSON(content), privateKey);
        if (decrypt == null) {
            decrypt = "{}";
        }
        this.body = new ByteArrayInputStream(decrypt.getBytes());
    }

    @Override
    public InputStream getBody() {
        return body;
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }
}