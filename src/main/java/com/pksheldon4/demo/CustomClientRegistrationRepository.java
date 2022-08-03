package com.pksheldon4.demo;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Component
public class CustomClientRegistrationRepository implements ClientRegistrationRepository, Iterable<ClientRegistration> {


    private final InMemoryClientRegistrationRepository clientRegistrationRepository;

    public CustomClientRegistrationRepository(OAuth2ClientProperties properties) {
        List<ClientRegistration> registrations = new ArrayList<>(
                OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(properties).values()) ;
        this.clientRegistrationRepository = new InMemoryClientRegistrationRepository(registrations);
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return clientRegistrationRepository.findByRegistrationId(registrationId);
    }

    @Override
    public Iterator<ClientRegistration> iterator() {
        return this.clientRegistrationRepository.iterator();
    }
}