package io.r2.wowza.webrtc_dtls;

import com.wowza.wms.certificate.CertificateHolderX509;
import com.wowza.wms.util.CertificateUtils;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class SelfSignedCertificateHolderTest {
    @Test
    public void testForceRegenerateCertificate() throws Exception {
        CertificateHolderX509 certHolder = CertificateUtils.loadCertificateX509(
                "selfsigned:testdomain.com",
                "secret", "server");

        assertThat(certHolder).isInstanceOf(SelfSignedCertificateHolder.class);

        Date d1 = ((X509Certificate)certHolder.getCertificate()).getNotAfter();

        Thread.sleep(1100);

        ((SelfSignedCertificateHolder)certHolder).forceRegenerateCertificate();

        Date d2 = ((X509Certificate)certHolder.getCertificate()).getNotAfter();

        assertThat(d2).isAfter(d1);
    }

}