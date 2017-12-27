package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import okhttp3.Authenticator;
import okhttp3.Challenge;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

/**
 * A dispatching authenticator which can be used with multiple auth schemes.
 */
public class DispatchingAuthenticator implements CachingAuthenticator {
    private final Map<String, Authenticator> authenticatorRegistry;
    private final Map<String, CachingAuthenticator> cachingRegistry;
    private final boolean requireAuthScheme;

    private DispatchingAuthenticator(Map<String, Authenticator> registry, boolean requireAuthScheme) {
        this.requireAuthScheme = requireAuthScheme;
        authenticatorRegistry = registry;
        cachingRegistry = new LinkedHashMap<>();
        for (Map.Entry<String, Authenticator> entry : authenticatorRegistry.entrySet()) {
            if (entry.getValue() instanceof CachingAuthenticator) {
                cachingRegistry.put(entry.getKey(), (CachingAuthenticator) entry.getValue());
            }
        }
    }

    @Override
    public Request authenticate(Route route, Response response) throws IOException {
        List<Challenge> challenges = response.challenges();
        if (!challenges.isEmpty()) {
            for (Challenge challenge : challenges) {
                final String scheme = challenge.scheme();
                Authenticator authenticator = null;
                if (scheme != null) {
                    authenticator = authenticatorRegistry.get(scheme.toLowerCase(Locale.getDefault()));
                }
                if (authenticator != null) {
                    return authenticator.authenticate(route, response);
                }
            }
        }
        if (requireAuthScheme) {
            throw new IllegalArgumentException("unsupported auth scheme " + challenges);
        }
        return null;
    }

    @Override
    public Request authenticateWithState(Route route, Request request) throws IOException {
        for (Map.Entry<String, CachingAuthenticator> authenticatorEntry : cachingRegistry.entrySet()) {
            final Request authRequest = authenticatorEntry.getValue().authenticateWithState(route, request);
            if (authRequest != null) {
                return authRequest;
            }
        }
        return null;
    }

    public static final class Builder {
        private final Map<String, Authenticator> registry = new LinkedHashMap<>();
        private boolean requireAuthScheme = true;

        public Builder with(String scheme, Authenticator authenticator) {
            registry.put(scheme.toLowerCase(Locale.getDefault()), authenticator);
            return this;
        }

        public Builder requireAuthScheme(boolean requireAuthScheme) {
            this.requireAuthScheme = requireAuthScheme;
            return this;
        }

        public DispatchingAuthenticator build() {
            return new DispatchingAuthenticator(registry, requireAuthScheme);
        }
    }
}

