package cn.omisheep.authz.support.http;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class SupportServlet extends HttpServlet {


    public void init() throws ServletException {
        initAuthEnv();
    }


    public void initAuthEnv() {
        System.out.println("initAuthEnv");
    }

    public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();
        String requestURI  = request.getRequestURI();

        response.setCharacterEncoding("utf-8");

        if (contextPath == null) { // root context
            contextPath = "";
        }
        String uri  = contextPath + servletPath;
        String path = requestURI.substring(contextPath.length() + servletPath.length());
        System.out.println(uri);
        System.out.println(path);
    }


}
