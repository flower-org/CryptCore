package com.flower.crypt;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PkiUtilTest {
    @Test
    public void testSignatures() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair = PkiUtil.generateRsa2048KeyPair();

        String data = "MyData";

        String sign = PkiUtil.signData(data, keyPair.getPrivate());
        boolean verified = PkiUtil.verifySignature(data, sign, keyPair.getPublic());

        assertTrue(verified);
    }

    @Test
    public void testRsaEncryption()
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        KeyPair keyPair = PkiUtil.generateRsa2048KeyPair();

        String data = "MyData";

        String encrypted1 = PkiUtil.encrypt(data, keyPair.getPrivate());
        assertEquals(data, PkiUtil.decrypt(encrypted1, keyPair.getPublic()));

        String encrypted2 = PkiUtil.encrypt(data, keyPair.getPublic());
        assertEquals(data, PkiUtil.decrypt(encrypted2, keyPair.getPrivate()));
    }


    @Test
    void testSignaturesAreIdentical() throws Exception {
        // Generate a test RSA keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Prepare sample data
        byte[] testData = "Hello, this is a test message".getBytes(UTF_8);

        // Sign with streaming method
        InputStream data1 = new ByteArrayInputStream(testData);
        byte[] sig1 = PkiUtil.signData(data1, kp.getPrivate());

        // Sign with quick method
        InputStream data2 = new ByteArrayInputStream(testData);
        byte[] sig2 = PkiUtil.signDataQuick(data2, kp.getPrivate());

        // Assert signatures are identical
        assertArrayEquals(sig1, sig2, "Signatures should be identical");
    }

    @Test
    void testVerificationWorks() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] testData = "Another test message".getBytes(UTF_8);

        // Sign with quick method
        InputStream data = new ByteArrayInputStream(testData);
        byte[] sig = PkiUtil.signDataQuick(data, kp.getPrivate());

        // Verify with standard SHA256withRSA
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(kp.getPublic());
        verifier.update(testData);
        assertTrue(verifier.verify(sig), "Signature should verify correctly");
    }

    @Test
    void testDifferentDataProducesDifferentSignatures() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] dataA = "Message A".getBytes(UTF_8);
        byte[] dataB = "Message B".getBytes(UTF_8);

        byte[] sigA = PkiUtil.signDataQuick(new ByteArrayInputStream(dataA), kp.getPrivate());
        byte[] sigB = PkiUtil.signDataQuick(new ByteArrayInputStream(dataB), kp.getPrivate());

        assertFalse(java.util.Arrays.equals(sigA, sigB), "Different messages should not produce identical signatures");
    }

    @Test
    void testSignaturesAreIdenticalForByteArray() throws Exception {
        // Generate a test RSA keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Sample data
        byte[] testData = "Hello, byte array signing".getBytes(UTF_8);

        // Sign with standard method
        byte[] sig1 = PkiUtil.signData(testData, kp.getPrivate());

        // Sign with quick method
        byte[] sig2 = PkiUtil.signDataQuick(testData, kp.getPrivate());

        // Assert signatures are identical
        assertArrayEquals(sig1, sig2, "Signatures should be identical for byte[] input");
    }

    @Test
    void testVerificationWorksForByteArray() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] testData = "Verification test message".getBytes(UTF_8);

        // Sign with quick method
        byte[] sig = PkiUtil.signDataQuick(testData, kp.getPrivate());

        // Verify with public key
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(kp.getPublic());
        verifier.update(testData);
        assertTrue(verifier.verify(sig), "Signature should verify correctly with public key");
    }

    @Test
    void testDifferentByteArraysProduceDifferentSignatures() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] dataA = "Message A".getBytes(UTF_8);
        byte[] dataB = "Message B".getBytes(UTF_8);

        byte[] sigA = PkiUtil.signDataQuick(dataA, kp.getPrivate());
        byte[] sigB = PkiUtil.signDataQuick(dataB, kp.getPrivate());

        assertFalse(java.util.Arrays.equals(sigA, sigB),
                "Different byte[] inputs should not produce identical signatures");
    }
}
