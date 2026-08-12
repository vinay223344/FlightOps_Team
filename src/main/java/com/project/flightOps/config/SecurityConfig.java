package com.project.flightOps.config;

import com.project.flightOps.exception.JwtAccessDeniedHandler;
import com.project.flightOps.exception.JwtAuthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtAuthEntryPoint jwtAuthEntryPoint;

    @Autowired
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(jwtAuthEntryPoint)       // 401 handler
                        .accessDeniedHandler(jwtAccessDeniedHandler))       // 403 handler

                .authorizeHttpRequests(auth -> auth

                        // ── Public ──────────────────────────────────────────────────
                        .requestMatchers("/api/auth/**").permitAll()

                        // ── Module 1: IAM ────────────────────────────────────────────
                        .requestMatchers(HttpMethod.POST,  "/api/auth/logout").authenticated()
                        .requestMatchers(HttpMethod.POST,  "/api/users").hasRole("Admin")
                        .requestMatchers(HttpMethod.GET,   "/api/users").hasRole("Admin")
                        .requestMatchers(HttpMethod.GET,   "/api/users/{id}").hasRole("Admin")
                        .requestMatchers(HttpMethod.PATCH, "/api/users/{id}").hasRole("Admin")
                        .requestMatchers(HttpMethod.GET,   "/api/audit").hasRole("Admin")

                        // ── Module 2: Flights & Handling Requests ─────────────────────
                        .requestMatchers(HttpMethod.POST,  "/api/flights").hasRole("Admin")
                        .requestMatchers(HttpMethod.GET,   "/api/flights").authenticated()
                        .requestMatchers(HttpMethod.GET,   "/api/flights/{id}").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/api/flights/{id}/status").hasRole("Admin")

                        .requestMatchers(HttpMethod.POST,  "/api/handling-requests")
                        .hasRole("AirlineCoordinator")
                        .requestMatchers(HttpMethod.GET,   "/api/handling-requests")
                        .hasAnyRole("AirlineCoordinator", "GroundSupervisor", "Admin")
                        .requestMatchers(HttpMethod.PATCH, "/api/handling-requests/{id}/confirm")
                        .hasRole("GroundSupervisor")
                        .requestMatchers(HttpMethod.PATCH, "/api/handling-requests/{id}/reject")
                        .hasRole("GroundSupervisor")
                        .requestMatchers(HttpMethod.GET, "/api/handling-requests/byUser/{userId}")
                        .hasAnyRole("AirlineCoordinator", "GroundSupervisor")

                        // ── Module 3: Turnaround ──────────────────────────────────────
                        .requestMatchers(HttpMethod.GET,   "/api/turnarounds").hasAnyRole("Admin", "GroundSupervisor", "RampOfficer", "AirlineCoordinator")
                        .requestMatchers(HttpMethod.GET,   "/api/turnarounds/{id}").hasAnyRole("GroundSupervisor", "RampOfficer")
                        .requestMatchers(HttpMethod.PATCH, "/api/turnarounds/{id}/complete").hasRole("GroundSupervisor")

                        .requestMatchers(HttpMethod.GET,   "/api/turnarounds/{id}/milestones")
                        .hasAnyRole("GroundSupervisor", "RampOfficer")
                        .requestMatchers(HttpMethod.PATCH, "/api/turnarounds/{id}/milestones/{milestoneId}/complete")
                        .hasRole("RampOfficer")
                        .requestMatchers(HttpMethod.GET,   "/api/turnarounds/{id}/milestones/overdue")
                        .hasRole("GroundSupervisor")

                        // ── Module 4: GSE ─────────────────────────────────────────────
                        .requestMatchers(HttpMethod.POST,  "/api/equipment").hasAnyRole("Admin", "GSEManager")
                        .requestMatchers(HttpMethod.GET,   "/api/equipment").hasAnyRole("Admin", "GSEManager")
                        .requestMatchers(HttpMethod.GET,   "/api/equipment/{id}").hasRole("GSEManager")
                        .requestMatchers(HttpMethod.PATCH, "/api/equipment/{id}/status").hasRole("GSEManager")

                        .requestMatchers(HttpMethod.POST,  "/api/allocations").hasRole("GSEManager")
                        .requestMatchers(HttpMethod.GET,   "/api/allocations").hasRole("GSEManager")
                        .requestMatchers(HttpMethod.PATCH, "/api/allocations/{id}/release").hasRole("GSEManager")

                        .requestMatchers(HttpMethod.POST,  "/api/equipment/{id}/maintenance").hasRole("GSEManager")
                        .requestMatchers(HttpMethod.GET,   "/api/equipment/{id}/maintenance").hasRole("GSEManager")

                        // ── Module 5: Passenger / Gate ────────────────────────────────
                        .requestMatchers(HttpMethod.POST,  "/api/counters").hasRole("PassengerAgent")
                        .requestMatchers(HttpMethod.GET,   "/api/counters").hasAnyRole("PassengerAgent", "GroundSupervisor")
                        .requestMatchers(HttpMethod.PATCH, "/api/counters/{id}/close").hasRole("PassengerAgent")

                        .requestMatchers(HttpMethod.POST,  "/api/gates").hasRole("PassengerAgent")
                        .requestMatchers(HttpMethod.GET,   "/api/gates").hasAnyRole("PassengerAgent", "GroundSupervisor")
                        .requestMatchers(HttpMethod.PATCH, "/api/gates/{id}/status").hasRole("PassengerAgent")

                        .requestMatchers(HttpMethod.POST,  "/api/special-assistance").hasRole("PassengerAgent")
                        .requestMatchers(HttpMethod.GET,   "/api/special-assistance").hasRole("PassengerAgent")
                        .requestMatchers(HttpMethod.PATCH, "/api/special-assistance/{id}/complete").hasRole("PassengerAgent")

                        // ── Module 6: Baggage ─────────────────────────────────────────
                        .requestMatchers(HttpMethod.POST,  "/api/baggage-operations").hasRole("RampOfficer")
                        .requestMatchers(HttpMethod.GET,   "/api/baggage-operations").hasAnyRole("RampOfficer", "GroundSupervisor")
                        .requestMatchers(HttpMethod.PATCH, "/api/baggage-operations/{id}/complete").hasRole("RampOfficer")

                        .requestMatchers(HttpMethod.POST,  "/api/mishandled-baggage").hasRole("RampOfficer")
                        .requestMatchers(HttpMethod.GET,   "/api/mishandled-baggage").hasAnyRole("RampOfficer", "GroundSupervisor")
                        .requestMatchers(HttpMethod.PATCH, "/api/mishandled-baggage/{id}/resolve").hasRole("RampOfficer")

                        // ── Module 7: Analytics ───────────────────────────────────────
                        .requestMatchers(HttpMethod.GET, "/api/analytics/turnaround").hasAnyRole("Admin", "GroundSupervisor")
                        .requestMatchers(HttpMethod.GET, "/api/analytics/sla-breaches").hasAnyRole("Admin", "GroundSupervisor")
                        .requestMatchers(HttpMethod.GET, "/api/analytics/gse-utilisation").hasAnyRole("Admin", "GSEManager")
                        .requestMatchers(HttpMethod.GET, "/api/analytics/baggage-discrepancy").hasAnyRole("Admin", "GroundSupervisor")
                        .requestMatchers(HttpMethod.GET, "/api/analytics/summary").hasRole("Admin")

                        // ── Module 8: Notifications (each user sees only their own) ───
                        .requestMatchers("/api/notifications/**").authenticated()
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-ui.html"
                        ).permitAll()


                        .anyRequest().authenticated()
                )

                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ── Auth provider ─────────────────────────────────────────────────────────

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ── CORS ──────────────────────────────────────────────────────────────────

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:5173", "http://localhost:5174","https://flightopspod7.onrender.com"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }

}
