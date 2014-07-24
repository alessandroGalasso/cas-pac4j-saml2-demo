package it.comp.app.Controller;


import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.access.prepost.PreAuthorize;

@Configuration
@EnableAspectJAutoProxy //@PreAuthorize("hasRole('S') ")
public class appConfiguration {
}
