package com.company.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;


    // роли админа имеют доступ к url /admin/**
    // роли юзеров имеют доступ к url /user/**
    // вручную настроенный 403 access denied handler
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // отключение защиты от межсайтовой подделки запроса, т.к. не будут обрабатываться запросы
        // без определенного csrf.token
        http.csrf().disable()
                // авторизация запросов, указать какие запросы и кому будут доступны
                .authorizeRequests()
                    .antMatchers("/", "/home", "/about").permitAll()
                    .antMatchers("/admin/**").hasAnyRole("ADMIN")
                    .antMatchers("/user/**").hasAnyRole("USER")
                // все остальные запросы будут доступны всем, но после аутентификации
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll()
                    .and()
                // обработка отказа в доступе к url
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler);

    }

    // создание двух пользователей - admin и user. Создаем их в памяти
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("password").roles("USER")
                .and()
                .withUser("admin").password("password").roles("ADMIN");
    }


}

/*

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    // сервис, который получает пользователя из базы по имени
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    // Кодировщик пароля
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        return bCryptPasswordEncoder;
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        // Установка сервиса для поиска пользователя в базе данных
        // Установка кодировщика пароля
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Выключение защиты от межсайтовой подделки запроса
        http.csrf().disable();

        // Страницы, которые не требуют аутентификации
        http.authorizeRequests().antMatchers("/", "/login", "/logout").permitAll();

        // /userInfo страница требует авторизации как USER или ADMIN
        // Если нет авторизации, то пользователь будет перенаправлен на страницу /login
        http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')");

        // Только для ADMIN
        http.authorizeRequests().antMatchers("/admin").access("hasRole('ROLE_ADMIN')");

        // Когда пользователь авторизирован, например, как USER
        // Но доступ только для ADMIN
        // Будет выброшено исключение AccessDeniedException
        http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");

        // Конфигурация для формы входа
        http.authorizeRequests().and().formLogin()//
                // Submit URL of login page.
                .loginProcessingUrl("/j_spring_security_check") // Submit URL
                .loginPage("/login")//
                .defaultSuccessUrl("/userAccountInfo")//
                .failureUrl("/login?error=true")//
                .usernameParameter("username")//
                .passwordParameter("password")
                // Config for Logout Page
                .and().logout().logoutUrl("/logout").logoutSuccessUrl("/logoutSuccessful");

    }
}

*/