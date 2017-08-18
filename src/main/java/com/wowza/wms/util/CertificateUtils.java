package com.wowza.wms.util;

import com.wowza.wms.certificate.CertificateHolderX509;
import com.wowza.wms.logging.WMSLoggerFactory;
import io.r2.wowza.webrtc_dtls.ReloadablePEMCertificateHolder;
import io.r2.wowza.webrtc_dtls.SelfSignedCertificateHolder;

import java.security.cert.Certificate;

/**
 * Replacement certificate utils for Wowza
 * Used by webrtc/dtls
 *  - support for (reloadable) PEM certificates added
 *  - support for self signed certificates (generated on the fly) added
 * Original class is copied to CertificateUtils0 by build script, default functions are delegated there
 */
public class CertificateUtils {

    private static final String PREFIX_PEM = "pem:";
    private static final String PREFIX_LETSENCRYPT = "letsencrypt:";
    private static final String PREFIX_SELFSIGNED = "selfsigned:";

    /**
     * getFingerPrint is delegated to original implementation
     */
    public static String getFingerprint(Certificate certificate) {
        return CertificateUtils0.getFingerprint(certificate);
    }

    /**
     * This method should read a certificate from the specified keystore
     * Overridden method checks for special filenames:
     * - "pem:path" - load single pem file (containing key and certificate chain)
     * - "letsencrypt:/etc/letsencrypt/live/domain.com" - load from letsencrypt directory, multiple pem files
     * - "selfsigned:domain.com" - generate a self signed certificate for domain.com
     * - everything else is delegated to original (eg. .jks files)
     * @param keystorePath     path to the keystore
     * @param keystorePassword keystore password, currently not used, only unencrypted keys supported (when loading from pem)
     * @param alias            not used when loading from pem
     * @return may return null in case of error
     */
    public static CertificateHolderX509 loadCertificateX509(String keystorePath, String keystorePassword, String alias) {
        if (keystorePath.startsWith(PREFIX_PEM)) {
            return ReloadablePEMCertificateHolder.create(keystorePath.substring(PREFIX_PEM.length()));
        }
        else if (keystorePath.startsWith(PREFIX_LETSENCRYPT)) {
            String basePath = keystorePath.substring(PREFIX_LETSENCRYPT.length());
            if (!basePath.endsWith("/")) basePath = basePath + "/";
            return ReloadablePEMCertificateHolder.create(basePath+"fullchain.pem", basePath+"privkey.pem");
        }
        else if (keystorePath.startsWith(PREFIX_SELFSIGNED)) {
            String domain = keystorePath.substring(PREFIX_SELFSIGNED.length());
            try {
                return new SelfSignedCertificateHolder(domain);
            }
            catch (Exception e) {
                WMSLoggerFactory.getLogger(CertificateUtils.class)
                        .error("Error generating self signed certificate", e);
                return null;
            }
        }
        else {
            // fall back to the original loader in case of no known prefixes
            return CertificateUtils0.loadCertificateX509(keystorePath, keystorePassword, alias);
        }
    }

}
