//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package ru.spandco.querysign.server.CMS;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Null;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CMSVersion;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateChoices;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateSet;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifiers;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncapsulatedContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.IssuerAndSerialNumber;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureValue;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfos;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;
import ru.CryptoPro.JCP.tools.Array;

public class CMS {
    private static final String CMS_FILE = "cms_data_sgn";
    private static final String CMS_FILE_PATH;
    private static final String CMS_FILE_PATH_2012_256;
    private static final String CMS_FILE_PATH_2012_512;
    private static final String CMS_FILE_D = "cms_data_d_sgn";
    private static final String CMS_FILE_D_PATH;
    private static final String CMS_FILE_D_PATH_2012_256;
    private static final String CMS_FILE_D_PATH_2012_512;

    private CMS() {
    }

    public static void main(String[] var0) throws Exception {
        main("gost_dup", CMStools.SIGN_KEY_PASSWORD, CMS_FILE_PATH, CMS_FILE_D_PATH, "JCP");
        main("client_key_2012_256", CMStools.SIGN_KEY_PASSWORD_2012_256, CMS_FILE_PATH_2012_256, CMS_FILE_D_PATH_2012_256, "JCP");
        main("client_key_2012_512", CMStools.SIGN_KEY_PASSWORD_2012_512, CMS_FILE_PATH_2012_512, CMS_FILE_D_PATH_2012_512, "JCP");
    }

    private static void main(String var0, char[] var1, String var2, String var3, String var4) throws Exception {
        byte[] var5 = Array.readFile(CMStools.DATA_FILE_PATH);
        PrivateKey var6 = CMStools.loadKey(var0, var1);
        Certificate var7 = CMStools.loadCertificate(var0);
        Array.writeFile(var2, CMSSignEx(var5, var6, var7, false, var4));
        CMSVerifyEx(Array.readFile(var2), var7, (byte[])null, var4);
        Array.writeFile(var3, CMSSignEx(var5, var6, var7, true, var4));
        CMSVerifyEx(Array.readFile(var3), var7, var5, var4);
    }

    public static byte[] CMSSign(byte[] var0, PrivateKey var1, Certificate var2, boolean var3) throws Exception {
        return CMSSignEx(var0, var1, var2, var3, "JCP");
    }

    public static byte[] CMSSignEx(byte[] var0, PrivateKey var1, Certificate var2, boolean var3, String var4) throws Exception {
        String var5 = var1.getAlgorithm();
        String var6 = AlgorithmUtility.keyAlgToSignatureOid(var5);
        Signature var7 = Signature.getInstance(var6, var4);
        var7.initSign(var1);
        var7.update(var0);
        byte[] var8 = var7.sign();
        return createCMSEx(var0, var8, var2, var3);
    }

    public static byte[] createCMS(byte[] var0, byte[] var1, Certificate var2, boolean var3) throws Exception {
        return createCMSEx(var0, var1, var2, var3);
    }

    public static byte[] createCMSEx(byte[] var0, byte[] var1, Certificate var2, boolean var3) throws Exception {
        String var4 = var2.getPublicKey().getAlgorithm();
        String var5 = AlgorithmUtility.keyAlgToDigestOid(var4);
        String var6 = AlgorithmUtility.keyAlgToKeyAlgorithmOid(var4);
        ContentInfo var7 = new ContentInfo();
        var7.contentType = new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.7.2")).value);
        SignedData var8 = new SignedData();
        var7.content = var8;
        var8.version = new CMSVersion(1L);
        var8.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        DigestAlgorithmIdentifier var9 = new DigestAlgorithmIdentifier((new OID(var5)).value);
        var9.parameters = new Asn1Null();
        var8.digestAlgorithms.elements[0] = var9;
        if (var3) {
            var8.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.7.1")).value), (Asn1OctetString)null);
        } else {
            var8.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier((new OID("1.2.840.113549.1.7.1")).value), new Asn1OctetString(var0));
        }

        var8.certificates = new CertificateSet(1);
        ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate var10 = new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        Asn1BerDecodeBuffer var11 = new Asn1BerDecodeBuffer(var2.getEncoded());
        var10.decode(var11);
        var8.certificates.elements = new CertificateChoices[1];
        var8.certificates.elements[0] = new CertificateChoices();
        var8.certificates.elements[0].set_certificate(var10);
        var8.signerInfos = new SignerInfos(1);
        var8.signerInfos.elements[0] = new SignerInfo();
        var8.signerInfos.elements[0].version = new CMSVersion(1L);
        var8.signerInfos.elements[0].sid = new SignerIdentifier();
        byte[] var12 = ((X509Certificate)var2).getIssuerX500Principal().getEncoded();
        Asn1BerDecodeBuffer var13 = new Asn1BerDecodeBuffer(var12);
        Name var14 = new Name();
        var14.decode(var13);
        CertificateSerialNumber var15 = new CertificateSerialNumber(((X509Certificate)var2).getSerialNumber());
        var8.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(var14, var15));
        var8.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier((new OID(var5)).value);
        var8.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        var8.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier((new OID(var6)).value);
        var8.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
        var8.signerInfos.elements[0].signature = new SignatureValue(var1);
        Asn1BerEncodeBuffer var16 = new Asn1BerEncodeBuffer();
        var7.encode(var16, true);
        return var16.getMsgCopy();
    }

    /** @deprecated */
    public static void CMSVerify(byte[] var0, Certificate var1, byte[] var2) throws Exception {
        CMSVerifyEx(var0, var1, var2, "JCP");
    }

    /** @deprecated */
    public static void CMSVerifyEx(byte[] var0, Certificate var1, byte[] var2, String var3) throws Exception {
        String var4 = var1.getPublicKey().getAlgorithm();
        String var5 = AlgorithmUtility.keyAlgToDigestOid(var4);
        String var6 = AlgorithmUtility.keyAlgToSignatureOid(var4);
        Asn1BerDecodeBuffer var8 = new Asn1BerDecodeBuffer(var0);
        ContentInfo var9 = new ContentInfo();
        var9.decode(var8);
        if (!(new OID("1.2.840.113549.1.7.2")).eq(var9.contentType.value)) {
            throw new Exception("Not supported");
        } else {
            SignedData var10 = (SignedData)var9.content;
            if (var10.version.value != 1L) {
                throw new Exception("Incorrect version");
            } else if (!(new OID("1.2.840.113549.1.7.1")).eq(var10.encapContentInfo.eContentType.value)) {
                throw new Exception("Nested not supported");
            } else {
                byte[] var11 = null;
                if (var2 != null) {
                    var11 = var2;
                } else if (var10.encapContentInfo.eContent != null) {
                    var11 = var10.encapContentInfo.eContent.value;
                }

                if (var11 == null) {
                    throw new Exception("No content");
                } else {
                    OID var12 = null;
                    DigestAlgorithmIdentifier var13 = new DigestAlgorithmIdentifier((new OID(var5)).value);

                    int var7;
                    for(var7 = 0; var7 < var10.digestAlgorithms.elements.length; ++var7) {
                        if (var10.digestAlgorithms.elements[var7].algorithm.equals(var13.algorithm)) {
                            var12 = new OID(var10.digestAlgorithms.elements[var7].algorithm.value);
                            break;
                        }
                    }

                    if (var12 == null) {
                        throw new Exception("Unknown digest");
                    } else {
                        int var14 = -1;
                        byte[] var16;
                        if (var10.certificates != null) {
                            for(var7 = 0; var7 < var10.certificates.elements.length; ++var7) {
                                Asn1BerEncodeBuffer var15 = new Asn1BerEncodeBuffer();
                                var10.certificates.elements[var7].encode(var15);
                                var16 = var15.getMsgCopy();
                                if (Arrays.equals(var16, var1.getEncoded())) {
                                    System.out.println("Certificate: " + ((X509Certificate)var1).getSubjectDN());
                                    var14 = var7;
                                    break;
                                }
                            }

                            if (var14 == -1) {
                                throw new Exception("Not signed on certificate.");
                            }
                        } else {
                            if (var1 == null) {
                                throw new Exception("No certificate found.");
                            }

                            var14 = 0;
                        }

                        SignerInfo var19 = var10.signerInfos.elements[var14];
                        if (var19.version.value != 1L) {
                            throw new Exception("Incorrect version");
                        } else if (!var12.equals(new OID(var19.digestAlgorithm.algorithm.value))) {
                            throw new Exception("Not signed on certificate.");
                        } else {
                            var16 = var19.signature.value;
                            Signature var17 = Signature.getInstance(var6, var3);
                            var17.initVerify(var1);
                            var17.update(var11);
                            boolean var18 = var17.verify(var16);
                            if (var18) {
                                if (CMStools.logger != null) {
                                    CMStools.logger.info("Valid signature");
                                }

                            } else {
                                throw new Exception("Invalid signature.");
                            }
                        }
                    }
                }
            }
        }
    }

    public static void verify(byte[] var0, X509Certificate var1, Signature var2) throws Exception {
        Asn1BerDecodeBuffer var4 = new Asn1BerDecodeBuffer(var0);
        ContentInfo var5 = new ContentInfo();
        var5.decode(var4);
        if (!(new OID("1.2.840.113549.1.7.2")).eq(var5.contentType.value)) {
            throw new Exception("Not supported");
        } else {
            SignedData var6 = (SignedData)var5.content;
            if (var6.version.value != 1L) {
                throw new Exception("Incorrect version");
            } else if (!(new OID("1.2.840.113549.1.7.1")).eq(var6.encapContentInfo.eContentType.value)) {
                throw new Exception("Nested not supported");
            } else {
                OID var7 = null;
                DigestAlgorithmIdentifier var8 = new DigestAlgorithmIdentifier((new OID("1.2.643.2.2.9")).value);

                int var3;
                for(var3 = 0; var3 < var6.digestAlgorithms.elements.length; ++var3) {
                    if (var6.digestAlgorithms.elements[var3].algorithm.equals(var8.algorithm)) {
                        var7 = new OID(var6.digestAlgorithms.elements[var3].algorithm.value);
                        break;
                    }
                }

                if (var7 == null) {
                    throw new Exception("Unknown digest");
                } else {
                    int var9 = -1;

                    byte[] var11;
                    for(var3 = 0; var3 < var6.certificates.elements.length; ++var3) {
                        Asn1BerEncodeBuffer var10 = new Asn1BerEncodeBuffer();
                        var6.certificates.elements[var3].encode(var10);
                        var11 = var10.getMsgCopy();
                        X509Certificate var12 = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(var11));
                        System.out.println(var12.getSubjectDN());
                        System.out.println(var1.getSubjectDN());
                        if (Arrays.equals(var11, var1.getEncoded())) {
                            var9 = var3;
                            break;
                        }
                    }

                    if (var9 == -1) {
                        throw new Exception("Not signed on certificate.");
                    } else {
                        SignerInfo var13 = var6.signerInfos.elements[var9];
                        if (var13.version.value != 1L) {
                            throw new Exception("Incorrect version");
                        } else if (!var7.equals(new OID(var13.digestAlgorithm.algorithm.value))) {
                            throw new Exception("Not signed on certificate.");
                        } else {
                            var11 = var13.signature.value;
                            boolean var14 = var2.verify(var11);
                            if (var14) {
                                if (CMStools.logger != null) {
                                    CMStools.logger.info("Valid signature");
                                }

                            } else {
                                throw new Exception("Invalid signature.");
                            }
                        }
                    }
                }
            }
        }
    }

    static {
        CMS_FILE_PATH = CMStools.TEST_PATH + CMStools.SEPAR + "cms_data_sgn" + ".p7b";
        CMS_FILE_PATH_2012_256 = CMStools.TEST_PATH + CMStools.SEPAR + "cms_data_sgn" + "_2012_256" + ".p7b";
        CMS_FILE_PATH_2012_512 = CMStools.TEST_PATH + CMStools.SEPAR + "cms_data_sgn" + "_2012_512" + ".p7b";
        CMS_FILE_D_PATH = CMStools.TEST_PATH + CMStools.SEPAR + "cms_data_d_sgn" + ".p7b";
        CMS_FILE_D_PATH_2012_256 = CMStools.TEST_PATH + CMStools.SEPAR + "cms_data_d_sgn" + "_2012_256" + ".p7b";
        CMS_FILE_D_PATH_2012_512 = CMStools.TEST_PATH + CMStools.SEPAR + "cms_data_d_sgn" + "_2012_512" + ".p7b";
    }
}
