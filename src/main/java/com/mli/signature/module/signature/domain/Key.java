package com.mli.signature.module.signature.domain;

import java.util.Objects;

public class Key {

    /**
     * 公钥
     **/
    private String publicKey;
    /**
     * 私钥
     **/
    private String privateKey;

    public Key() {
    }

    public Key(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return this.privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public Key publicKey(String publicKey) {
        setPublicKey(publicKey);
        return this;
    }

    public Key privateKey(String privateKey) {
        setPrivateKey(privateKey);
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Key)) {
            return false;
        }
        Key entity = (Key) o;
        return Objects.equals(publicKey, entity.publicKey) && Objects.equals(privateKey, entity.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, privateKey);
    }

    @Override
    public String toString() {
        return "{" +
                " publicKey='" + getPublicKey() + "'" +
                ", privateKey='" + getPrivateKey() + "'" +
                "}";
    }

}
