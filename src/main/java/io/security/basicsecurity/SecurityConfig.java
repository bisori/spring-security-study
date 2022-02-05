package io.security.basicsecurity;

import javax.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
        // http.authorizeRequests((requests) -> requests.anyRequest().authenticated());

        http.formLogin()
          .defaultSuccessUrl("/")
          .failureUrl("/login")
          .usernameParameter("userId")
          .passwordParameter("passwd")
          .loginProcessingUrl("/login_proc")
          .successHandler((request, response, authentication) -> {
              log.info("authentication: " + authentication.getName());
              response.sendRedirect("/");
          })
          .failureHandler((request, response, exception) -> {
              log.info("exception: " + exception.getMessage());
              response.sendRedirect("/login");
          })
          .permitAll();

        http.logout()
          .logoutUrl("/logout")
          .logoutSuccessUrl("/login")
          .addLogoutHandler((request, response, authentication) -> {
              HttpSession session = request.getSession();
              session.invalidate();
          })
          .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
          .deleteCookies("JSESSIONID", "remember");

        http.rememberMe()
          .rememberMeParameter("remember")
          .tokenValiditySeconds(3600)
          .userDetailsService(userDetailsService);

        http.sessionManagement()
          .sessionFixation().none();
    }
}
