package com.mli.signature.module.signature.domain;

import java.util.Objects;

/**
 * RSA
 * 
 * @version 1.0
 * @author D3031104
 */
public class RSAEntity {

    private Integer id;

    private String username;

    private String pub;

    private String signature;

    private String data;

    private String name;

    public RSAEntity() {
    }

    public RSAEntity(Integer id, String username, String pub, String signature, String data, String name) {
        this.id = id;
        this.username = username;
        this.pub = pub;
        this.signature = signature;
        this.data = data;
        this.name = name;
    }

    public Integer getId() {
        return this.id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPub() {
        return this.pub;
    }

    public void setPub(String pub) {
        this.pub = pub;
    }

    public String getSignature() {
        return this.signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getData() {
        return this.data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public RSAEntity id(Integer id) {
        setId(id);
        return this;
    }

    public RSAEntity username(String username) {
        setUsername(username);
        return this;
    }

    public RSAEntity pub(String pub) {
        setPub(pub);
        return this;
    }

    public RSAEntity signature(String signature) {
        setSignature(signature);
        return this;
    }

    public RSAEntity data(String data) {
        setData(data);
        return this;
    }

    public RSAEntity name(String name) {
        setName(name);
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof RSAEntity)) {
            return false;
        }
        RSAEntity rSAEntity = (RSAEntity) o;
        return Objects.equals(id, rSAEntity.id) && Objects.equals(username, rSAEntity.username)
                && Objects.equals(pub, rSAEntity.pub) && Objects.equals(signature, rSAEntity.signature)
                && Objects.equals(data, rSAEntity.data) && Objects.equals(name, rSAEntity.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, pub, signature, data, name);
    }

    @Override
    public String toString() {
        return "{" +
                " id='" + getId() + "'" +
                ", username='" + getUsername() + "'" +
                ", pub='" + getPub() + "'" +
                ", signature='" + getSignature() + "'" +
                ", data='" + getData() + "'" +
                ", name='" + getName() + "'" +
                "}";
    }

}
