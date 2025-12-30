package com.flower.crypt;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.google.common.base.Preconditions.checkNotNull;

public class HybridAesEncryptor {
    public static final String AES_CBC = "AES/CBC/PKCS5Padding";
    public static final String AES = "AES";

    public enum Mode {
        PUBLIC_KEY_ENCRYPT,
        PRIVATE_KEY_ENCRYPT
    }

    public static byte[] concatenateArrays(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    public static void encrypt(InputStream fis, OutputStream fos, Mode mode,
                               @Nullable PrivateKey privateKey, @Nullable PublicKey publicKey, @Nullable Integer length) throws Exception {
        byte[] key = Cryptor.generateAESKeyRaw();
        byte[] iv = Cryptor.generateAESIV();
        byte[] keyAndIv = concatenateArrays(key, iv);

        byte[] encryptedKeyIv;
        if (mode == Mode.PUBLIC_KEY_ENCRYPT) {
            encryptedKeyIv = PkiUtil.encrypt(keyAndIv, checkNotNull(publicKey));
        } else if (mode == Mode.PRIVATE_KEY_ENCRYPT) {
            encryptedKeyIv = PkiUtil.encrypt(keyAndIv, checkNotNull(privateKey));
        } else {
            throw new RuntimeException("Unsupported mode " + mode);
        }

        byte[] encryptedKeyIvWithLength = new byte[4 + encryptedKeyIv.length];

        // Prepend the length of the key (4 bytes) - BigEndian order to match ByteBuffer.putInt(keyLength)
        int encryptedKeyIvLength = encryptedKeyIv.length;
        encryptedKeyIvWithLength[0] = (byte) (encryptedKeyIvLength >> 24);
        encryptedKeyIvWithLength[1] = (byte) (encryptedKeyIvLength >> 16);
        encryptedKeyIvWithLength[2] = (byte) (encryptedKeyIvLength >> 8);
        encryptedKeyIvWithLength[3] = (byte) (encryptedKeyIvLength);

        // Copy the key into the result array
        System.arraycopy(encryptedKeyIv, 0, encryptedKeyIvWithLength, 4,
                encryptedKeyIv.length);

        SecretKeySpec aesKey = new SecretKeySpec(key, AES);
        IvParameterSpec aesIv = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_CBC);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv);

        fos.write(encryptedKeyIvWithLength);
        PkiUtil.encryptFile(aesKey, aesIv, fis, fos, length);
    }

    public static void decrypt(InputStream fis, OutputStream fos, Mode mode,
                               @Nullable PrivateKey privateKey, @Nullable PublicKey publicKey, @Nullable Integer length) throws Exception {
        try (DataInputStream dis = new DataInputStream(fis)) {
            int keyIvLength = dis.readInt();
            byte[] encryptedKeyIv = new byte[keyIvLength];
            int keyIvBytesRead = fis.read(encryptedKeyIv);

            byte[] keyIv;
            if (mode == Mode.PUBLIC_KEY_ENCRYPT) {
                keyIv = PkiUtil.decrypt(encryptedKeyIv, checkNotNull(privateKey));
            } else if (mode == Mode.PRIVATE_KEY_ENCRYPT) {
                keyIv = PkiUtil.decrypt(encryptedKeyIv, checkNotNull(publicKey));
            } else {
                throw new RuntimeException("Unsupported mode " + mode);
            }

            // Separate the key and IV
            byte[] key = new byte[32];
            byte[] iv = new byte[16];

            System.arraycopy(keyIv, 0, key, 0, 32);
            System.arraycopy(keyIv, 32, iv, 0, 16);

            SecretKeySpec aesKey = new SecretKeySpec(key, AES);
            IvParameterSpec aesIv = new IvParameterSpec(iv);

            Integer dataLength = length == null ? null : (length - (encryptedKeyIv.length + 4));
            PkiUtil.decryptFile(aesKey, aesIv, fis, fos, dataLength);
        }
    }
}
