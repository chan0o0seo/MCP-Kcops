package com.kcops.mcp;

import com.kcops.mcp.config.KcopsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(KcopsProperties.class)
public class KcopsApplication {

    public static void main(String[] args) {
        SpringApplication.run(KcopsApplication.class, args);
    }
}
