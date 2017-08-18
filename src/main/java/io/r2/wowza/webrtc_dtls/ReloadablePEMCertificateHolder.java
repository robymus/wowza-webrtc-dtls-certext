package io.r2.wowza.webrtc_dtls;

import com.wowza.wms.certificate.CertificateHolderX509;
import com.wowza.wms.logging.WMSLoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Subclass of CertificateHolderX509 to handle loading of certificate from PEM files and
 * automatic reloading of certificates when changed
 *
 * Note: as we don't know how the getCertificate and getKeyPair methods are invoked, this could
 * lead to inconsistency when reloading certificates and changing the private key as well:
 * it might be possible that the value returned for getCertificate and getKeyPair do not match.
 *
 * One solution could be to not generate new key pair upon certificate renewal.
 *
 * Note: this certificate holder can return only the final certifiate, not the full certificate chain
 *       apparently this is sufficient - however, the full certificate chain is loaded when available
 *       (for example for let's encrypt certificates) for future development.
 */
public class ReloadablePEMCertificateHolder extends CertificateHolderX509 {

    /** check for certificate change every 30 minutes */
    private static final long RELOAD_TIME_MINUTES = 30;

    private String pemFilesStr;
    private Path[] files;
    private long lastFileTime = 0L;
    private PemCertKey certKey = null;
    private Certificate certificate = null;
    private KeyPair keyPair = null;

    /** scheduler for the certificate refreshing task */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    /**
     * Internal constructor, loads the files and throws exception on failure
     * @param pemFiles the pem files to read
     */
    private ReloadablePEMCertificateHolder(String... pemFiles) throws IOException, CertificateException, NoSuchAlgorithmException {
        this.pemFilesStr = String.join(", ", pemFiles);
        files = Arrays.stream(pemFiles)
                .map(f -> FileSystems.getDefault().getPath(f))
                .collect(Collectors.toList()).toArray(new Path[0]);

        lastFileTime = getCertificateTime();
        if (lastFileTime < 0) throw new IOException("Error retrieving file times: "+pemFilesStr);
        forceReloadCertificate();

        // schedule modification check and reload
        scheduler.scheduleAtFixedRate(this::checkForReload, RELOAD_TIME_MINUTES, RELOAD_TIME_MINUTES, TimeUnit.MINUTES);
    }

    /**
     * Helper method to get the file modification time of the certificate file
     * @return -1 in case of error, otherwise time in milliseconds of last modification
     */
    long getCertificateTime() {
        try {
            long fileTime = 0;
            for (Path f : files) {
                fileTime = Math.max(
                        fileTime,
                        Files.readAttributes(f, BasicFileAttributes.class).lastModifiedTime().toMillis()
                );
            }
            return fileTime;
        }
        catch (IOException ie) {
            // log exception, but continue with the old certificate
            WMSLoggerFactory.getLogger(ReloadablePEMCertificateHolder.class)
                    .error("Error checking PEM certificate time: "+pemFilesStr, ie);
            return -1;
        }
    }

    /**
     * Scheduled method to check for reload and do reload certificates if needed
     */
    void checkForReload() {
        long fileTime = getCertificateTime();
        if (fileTime > lastFileTime) {
            try {
                forceReloadCertificate();
                lastFileTime = fileTime;
            } catch (IOException|CertificateException|NoSuchAlgorithmException e) {
                WMSLoggerFactory.getLogger(ReloadablePEMCertificateHolder.class)
                        .error("Error reloading PEM certificate: " + pemFilesStr, e);
            }
        }
    }

    /**
     * Reload certificates from files and update local certificate and keyPair variables
     * @throws IOException in case of error
     */
    void forceReloadCertificate() throws IOException, CertificateException, NoSuchAlgorithmException {
        InputStream in = MultiFileConcatSource.fromFiles(files).build();
        PemCertKey certKey = new PemCertKey(in);
        certificate = certKey.getCertificate();
        try {
            Key key = certKey.getPrivateKey();
            if (!(key instanceof PrivateKey)) throw new UnrecoverableKeyException("Key is not PrivateKey");
            keyPair = new KeyPair(certificate.getPublicKey(), (PrivateKey)key);
        }
        catch (UnrecoverableKeyException e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public void setCertificate(Certificate cert) {
        // not implemented, ignore
    }

    @Override
    public KeyPair getKeyPair() {
        return keyPair;
    }

    @Override
    public void setKeyPair(KeyPair kp) {
        // not implemented, ignore
    }

    /**
     * Factory method to create new instances
     * It handles exceptions, writes to log and returns null in case of error
     * @param pemFiles the files to load
     * @return the certificate holder or null in case of error
     */
    public static ReloadablePEMCertificateHolder create(String... pemFiles) {
        try {
            return new ReloadablePEMCertificateHolder(pemFiles);
        } catch (IOException|CertificateException|NoSuchAlgorithmException e) {
            WMSLoggerFactory.getLogger(ReloadablePEMCertificateHolder.class)
                .error("Error reading PEM certificate: "+String.join(", ", pemFiles), e);
            return null;
        }
    }
}
