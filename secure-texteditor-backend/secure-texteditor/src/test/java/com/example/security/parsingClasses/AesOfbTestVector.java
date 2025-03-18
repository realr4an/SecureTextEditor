package com.example.security.parsingClasses;

public class AesOfbTestVector {
    public final int count;
    public final String keyHex;
    public final String ivHex;
    public final String plaintextHex;
    public final String ciphertextHex;

    public AesOfbTestVector(int count, String keyHex, String ivHex, 
                            String plaintextHex, String ciphertextHex) {
        this.count = count;
        this.keyHex = keyHex;
        this.ivHex = ivHex;
        this.plaintextHex = plaintextHex;
        this.ciphertextHex = ciphertextHex;
    }
}