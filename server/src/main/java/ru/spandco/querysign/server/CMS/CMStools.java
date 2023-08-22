package ru.spandco.querysign.server.CMS;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.JCP.tools.JCPLogger;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;

public class CMStools {
    public static final String CERT_EXT = ".cer";
    public static final String CMS_EXT = ".p7b";
    public static final String SEPAR;
    public static String TEST_PATH;
    public static final String SIGN_KEY_NAME = "gost_dup";
    public static final String SIGN_KEY_NAME_CONT = "gostrdup.000";
    public static final char[] SIGN_KEY_PASSWORD;
    public static String SIGN_CERT_PATH;
    public static final String SIGN_KEY_NAME_2012_256 = "client_key_2012_256";
    public static final String SIGN_KEY_NAME_CONT_2012_256 = "clientrk.000";
    public static final char[] SIGN_KEY_PASSWORD_2012_256;
    public static String SIGN_CERT_PATH_2012_256;
    public static final String SIGN_KEY_NAME_2012_512 = "client_key_2012_512";
    public static final String SIGN_KEY_NAME_CONT_2012_512 = "clientrk.001";
    public static final char[] SIGN_KEY_PASSWORD_2012_512;
    public static String SIGN_CERT_PATH_2012_512;
    public static final String RECIP_KEY_NAME = "afevma_dup";
    public static final String RECIP_KEY_NAME_CONT = "afevmard.000";
    public static final char[] RECIP_KEY_PASSWORD;
    public static String RECIP_CERT_PATH;
    public static final String RECIP_KEY_NAME_2012_256 = "server_key_2012_256";
    public static final String RECIP_KEY_NAME_CONT_2012_256 = "serverrk.000";
    public static final char[] RECIP_KEY_PASSWORD_2012_256;
    public static String RECIP_CERT_PATH_2012_256;
    public static final String RECIP_KEY_NAME_2012_512 = "server_key_2012_512";
    public static final String RECIP_KEY_NAME_CONT_2012_512 = "serverrk.001";
    public static final char[] RECIP_KEY_PASSWORD_2012_512;
    public static String RECIP_CERT_PATH_2012_512;
    public static final String STORE_TYPE = "HDImageStore";
    public static final String KEY_ALG_NAME = "GOST3410DHEL";
    public static final String DIGEST_ALG_NAME = "GOST3411";
    public static final String KEY_ALG_NAME_2012_256 = "GOST3410DH_2012_256";
    public static final String DIGEST_ALG_NAME_2012_256 = "GOST3411_2012_256";
    public static final String KEY_ALG_NAME_2012_512 = "GOST3410DH_2012_512";
    public static final String DIGEST_ALG_NAME_2012_512 = "GOST3411_2012_512";
    public static final String SEC_KEY_ALG_NAME = "GOST28147";
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    public static final String STR_CMS_OID_ENVELOPED = "1.2.840.113549.1.7.3";
    public static final String STR_CMS_OID_CONT_TYP_ATTR = "1.2.840.113549.1.9.3";
    public static final String STR_CMS_OID_DIGEST_ATTR = "1.2.840.113549.1.9.4";
    public static final String STR_CMS_OID_SIGN_TYM_ATTR = "1.2.840.113549.1.9.5";
    public static final String STR_CMS_OID_TS = "1.2.840.113549.1.9.16.1.4";
    public static final String DIGEST_OID = "1.2.643.2.2.9";
    public static final String SIGN_OID = "1.2.643.2.2.19";
    public static final String DIGEST_OID_2012_256 = "1.2.643.7.1.1.2.2";
    public static final String SIGN_OID_2012_256 = "1.2.643.7.1.1.1.1";
    public static final String DIGEST_OID_2012_512 = "1.2.643.7.1.1.2.3";
    public static final String SIGN_OID_2012_512 = "1.2.643.7.1.1.1.2";
    public static final String DATA = "12345";
    public static final String DATA_FILE = "data.txt";
    public static String DATA_FILE_PATH;
    public static Logger logger;
    private static CertificateFactory cf;
    private static Certificate rootCert;

    public CMStools() {
    }

    public static void main(String[] var0) throws Exception {
        byte[] var1 = GostCertificateRequest.getEncodedRootCert("http://testca.cryptopro.ru/certsrv/");
        cf = CertificateFactory.getInstance("X509");
        rootCert = cf.generateCertificate(new ByteArrayInputStream(var1));
        createContainer("afevma_dup", RECIP_KEY_PASSWORD, "GOST3410DHEL", "GOST3411withGOST3410EL");
        createContainer("gost_dup", SIGN_KEY_PASSWORD, "GOST3410DHEL", "GOST3411withGOST3410EL");
        createContainer("server_key_2012_256", RECIP_KEY_PASSWORD_2012_256, "GOST3410DH_2012_256", "GOST3411_2012_256withGOST3410_2012_256");
        createContainer("client_key_2012_256", SIGN_KEY_PASSWORD_2012_256, "GOST3410DH_2012_256", "GOST3411_2012_256withGOST3410_2012_256");
        createContainer("server_key_2012_512", RECIP_KEY_PASSWORD_2012_512, "GOST3410DH_2012_512", "GOST3411_2012_512withGOST3410_2012_512");
        createContainer("client_key_2012_512", SIGN_KEY_PASSWORD_2012_512, "GOST3410DH_2012_512", "GOST3411_2012_512withGOST3410_2012_512");
        prepareCertsAndData();
    }

    public static void prepareCertsAndData() throws Exception {
        expCert("afevma_dup", RECIP_CERT_PATH);
        expCert("gost_dup", SIGN_CERT_PATH);
        expCert("server_key_2012_256", RECIP_CERT_PATH_2012_256);
        expCert("client_key_2012_256", SIGN_CERT_PATH_2012_256);
        expCert("server_key_2012_512", RECIP_CERT_PATH_2012_512);
        expCert("client_key_2012_512", SIGN_CERT_PATH_2012_512);
        Array.writeFile(DATA_FILE_PATH, "12345".getBytes());
    }

    private static void expCert(String var0, String var1) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore var2 = KeyStore.getInstance("HDImageStore");
        var2.load((InputStream)null, (char[])null);
        Certificate var3 = var2.getCertificate(var0);
        Array.writeFile(var1, var3.getEncoded());
    }

    private static void createContainer(String var0, char[] var1, String var2, String var3) throws Exception {
        JCPLogger.traceFormat("name: {0}\npassword: {1}\nkey alg name: {2}\nsign alg name: {3}", new Object[]{var0, var1, var2, var3});
        KeyPairGenerator var4 = KeyPairGenerator.getInstance(var2);
        KeyPair var5 = var4.generateKeyPair();
        GostCertificateRequest var6 = new GostCertificateRequest();
        var6.init(var2, false);
        var6.setPublicKeyInfo(var5.getPublic());
        var6.setSubjectInfo("CN=" + var0);
        var6.encodeAndSign(var5.getPrivate(), var3);
        byte[] var7 = var6.getEncodedCert("http://testca.cryptopro.ru/certsrv/");
        Certificate var8 = cf.generateCertificate(new ByteArrayInputStream(var7));
        Certificate[] var9 = new Certificate[]{var8, rootCert};
        JCPLogger.traceFormat("Cert: sn {0}, subject: {1}", new Object[]{((X509Certificate)var8).getSerialNumber().toString(16), ((X509Certificate)var8).getSubjectDN()});
        KeyStore var10 = KeyStore.getInstance("HDImageStore");
        var10.load((InputStream)null, (char[])null);
        var10.setKeyEntry(var0, var5.getPrivate(), var1, var9);
        JCPLogger.trace("OK!");
    }

    public static PrivateKey loadKey(String var0, char[] var1) throws Exception {
        KeyStore var2 = KeyStore.getInstance("HDImageStore");
        var2.load((InputStream)null, (char[])null);
        return (PrivateKey)var2.getKey(var0, var1);
    }

    public static Certificate loadCertificate(String var0) throws Exception {
        KeyStore var1 = KeyStore.getInstance("HDImageStore");
        var1.load((InputStream)null, (char[])null);
        return var1.getCertificate(var0);
    }

    public static Certificate readCertificate(String var0) throws IOException, CertificateException {
        FileInputStream var1 = null;
        BufferedInputStream var2 = null;

        Certificate var5;
        try {
            var1 = new FileInputStream(var0);
            var2 = new BufferedInputStream(var1);
            CertificateFactory var4 = CertificateFactory.getInstance("X.509");
            Certificate var3 = var4.generateCertificate(var2);
            var5 = var3;
        } finally {
            if (var2 != null) {
                var2.close();
            }

            if (var1 != null) {
                var1.close();
            }

        }

        return var5;
    }

    public static byte[] digestm(byte[] var0, String var1) throws Exception {
        return digestm(var0, var1, "JCP");
    }

    public static byte[] digestm(byte[] var0, String var1, String var2) throws Exception {
        ByteArrayInputStream var3 = new ByteArrayInputStream(var0);
        MessageDigest var4 = var2 != null ? MessageDigest.getInstance(var1, var2) : MessageDigest.getInstance(var1);
        DigestInputStream var5 = new DigestInputStream(var3, var4);

        while(var5.available() != 0) {
            var5.read();
        }

        return var4.digest();
    }

    static {
        SEPAR = File.separator;
        TEST_PATH = System.getProperty("user.dir") + SEPAR + ".." + SEPAR + "temp";
        SIGN_KEY_PASSWORD = "Pass1234".toCharArray();
        SIGN_CERT_PATH = TEST_PATH + SEPAR + "gost_dup" + ".cer";
        SIGN_KEY_PASSWORD_2012_256 = "pass1".toCharArray();
        SIGN_CERT_PATH_2012_256 = TEST_PATH + SEPAR + "client_key_2012_256" + ".cer";
        SIGN_KEY_PASSWORD_2012_512 = "pass3".toCharArray();
        SIGN_CERT_PATH_2012_512 = TEST_PATH + SEPAR + "client_key_2012_512" + ".cer";
        RECIP_KEY_PASSWORD = "security".toCharArray();
        RECIP_CERT_PATH = TEST_PATH + SEPAR + "afevma_dup" + ".cer";
        RECIP_KEY_PASSWORD_2012_256 = "pass2".toCharArray();
        RECIP_CERT_PATH_2012_256 = TEST_PATH + SEPAR + "server_key_2012_256" + ".cer";
        RECIP_KEY_PASSWORD_2012_512 = "pass4".toCharArray();
        RECIP_CERT_PATH_2012_512 = TEST_PATH + SEPAR + "server_key_2012_512" + ".cer";
        DATA_FILE_PATH = TEST_PATH + SEPAR + "data.txt";
        logger = Logger.getLogger("LOG");
        cf = null;
        rootCert = null;
    }
}

