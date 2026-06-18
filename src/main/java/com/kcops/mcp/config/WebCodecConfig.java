package com.kcops.mcp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
@Profile("!mock")
public class WebCodecConfig implements WebFluxConfigurer {

    private final KcopsProperties properties;

    public WebCodecConfig(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public void configureHttpMessageCodecs(ServerCodecConfigurer configurer) {
        configurer.defaultCodecs().maxInMemorySize(properties.getLimits().getMaxRequestBytes());
    }
}
