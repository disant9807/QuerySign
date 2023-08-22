package ru.spandco.querysign.server.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;

@Service("CertificateStoreService")
public class CertificateStoreService {

    private String CertificateStoreName= "HDImageStore";

    private  String CertificateName = "rootCert";

    public CertificateStoreService() {

    }

    public Map.Entry<X509Certificate, PrivateKey> GetCertificate (String storePath, String subjectName, char[] pass)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException {

        String certStoreName = (storePath != null && !storePath.isEmpty()) ?
                storePath : CertificateStoreName;
        String certSubjectName = (subjectName != null && !subjectName.isEmpty()) ?
                subjectName : CertificateName;

        return GetCertificateFromStore(certStoreName, certSubjectName, pass);
    }

    private Map.Entry<X509Certificate, PrivateKey> GetCertificateFromStore(String storeName, String subjectName, char[] storePassParam)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance(storeName);
        ks.load(null, (char[])storePassParam);

        X509Certificate cert = (X509Certificate)ks.getCertificate(subjectName);
        PrivateKey privateKey = (PrivateKey) ks.getKey(subjectName, storePassParam);

        return new AbstractMap.SimpleEntry<>(cert, privateKey);
    }
}
