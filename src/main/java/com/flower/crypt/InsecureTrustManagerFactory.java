package com.flower.crypt;

import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class InsecureTrustManagerFactory extends TrustManagerFactory {
    public static final InsecureTrustManagerFactory INSTANCE = new InsecureTrustManagerFactory();

    private static final TrustManager[] ALL_TRUSTING_MANAGERS = new TrustManager[]{
        new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // Accept all client certificates
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // Accept all server certificates
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0]; // Return an empty array
            }
        }
    };

    private static class InsecureTrustManagerFactorySpi extends TrustManagerFactorySpi {
        @Override
        protected void engineInit(KeyStore keyStore) {
            // no init
        }

        @Override
        protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
            // no init
        }

        @Override
        protected TrustManager[] engineGetTrustManagers() {
            return ALL_TRUSTING_MANAGERS;
        }
    }

    public InsecureTrustManagerFactory() {
        super(new InsecureTrustManagerFactory.InsecureTrustManagerFactorySpi(), null, "Insecure");
    }
}