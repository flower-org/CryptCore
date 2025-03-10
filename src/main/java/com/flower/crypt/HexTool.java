package com.flower.crypt;

import java.util.HexFormat;

public class HexTool {
    public static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    public static byte[] hexStringToByteArray(String hex) {
        return HexFormat.of().parseHex(hex);
    }
}
