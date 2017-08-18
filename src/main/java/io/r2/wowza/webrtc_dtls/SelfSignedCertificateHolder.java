package io.r2.wowza.webrtc_dtls;

import com.wowza.wms.certificate.CertificateHolderX509;
import com.wowza.wms.logging.WMSLoggerFactory;
import com.wowza.wms.util.CertificateUtils;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Subclass of CertificateHolderX509 which generates a self signed certificate for a specified domain
 * with a validity of 5 years and a new private key at every instantiation.
 *
 * This class uses the deprecated X509V1CertificateGenerator class. The replacing new class is not
 * present in bcprov 1.54, which is shipped with WMS 4.7.1
 */
@SuppressWarnings("deprecation")
public class SelfSignedCertificateHolder extends CertificateHolderX509 {

    private static long HOUR_MS = 3600_000L;
    private static long YEAR_MS = 365 * 24 * HOUR_MS;

    private static long CERT_EXPIRATION = YEAR_MS;
    private static long CERT_REGENERATE_THRESHOLD = 7 * 24 * HOUR_MS;
    private static long CERT_REGENERATE_TIMER_HOURS = 24;

    private String CN;
    private long expiration;

    /** scheduler for the certificate refreshing task */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    /**
     * Constructor to create a self signed certificate
     * @param CN the common name (CN) to use in the certificate, should be a domain name
     */
    public SelfSignedCertificateHolder(String CN) throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, InvalidKeyException {
        this.CN = CN;
        // generate key pair using standard java crypto
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        setKeyPair(keyPair);

        forceRegenerateCertificate();

        scheduler.scheduleAtFixedRate(this::checkForExpiration, CERT_REGENERATE_TIMER_HOURS, CERT_REGENERATE_TIMER_HOURS, TimeUnit.HOURS);
    }

    /**
     * Checks if the self signed certificate should be regenerated
     */
    void checkForExpiration() {
        if (System.currentTimeMillis() + CERT_REGENERATE_THRESHOLD >= expiration) {
            try {
                forceRegenerateCertificate();
            }
            catch (Exception e) {
                WMSLoggerFactory.getLogger(SelfSignedCertificateHolder.class)
                        .warn("Error regenerating self signed certificate", e);
            }
        }
    }

    /**
     * REgenerates the certificate, with new expiration date
     */
    void forceRegenerateCertificate() throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, InvalidKeyException {
        // generate self signed certificate using bouncycastle deprecated API
        org.bouncycastle.x509.X509V1CertificateGenerator certGen = new org.bouncycastle.x509.X509V1CertificateGenerator();
        X500Principal DN = new X500Principal("CN="+CN);

        long newExpiration = System.currentTimeMillis() + CERT_EXPIRATION;

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(DN);
        certGen.setIssuerDN(DN);
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * HOUR_MS));
        certGen.setNotAfter(new Date(newExpiration));
        certGen.setPublicKey(getKeyPair().getPublic());
        certGen.setSignatureAlgorithm("SHA256withRSA");

        X509Certificate certificate = certGen.generate(getKeyPair().getPrivate());

        // store in parent class
        setCertificate(certificate);
        // update expiration only if generating the certificate was successful (eg. retry on failure)
        expiration = newExpiration;
    }

}
