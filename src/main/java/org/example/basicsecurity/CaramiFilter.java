package org.example.basicsecurity;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;

// @Component
@WebFilter(urlPatterns = "/hello")  // WebFilter 쓸 때는 component 안 써도 됨 (이 버전에서는)
public class CaramiFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("caramiFilter.doFilter() 실행 전");
        filterChain.doFilter(servletRequest, servletResponse);
        System.out.println("caramiFilter.doFilter() 실행 후");
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
