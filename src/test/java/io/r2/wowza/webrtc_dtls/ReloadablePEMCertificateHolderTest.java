package io.r2.wowza.webrtc_dtls;

import com.wowza.wms.certificate.CertificateHolderX509;
import com.wowza.wms.util.CertificateUtils;
import com.wowza.wms.util.CertificateUtilsTest;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.file.*;
import java.util.Comparator;

public class ReloadablePEMCertificateHolderTest {

    Path tmpDir;

    @BeforeTest
    public void setUp() throws Exception {
        tmpDir = Files.createTempDirectory("certext-test");
    }

    @AfterTest
    public void tearDown() throws Exception {
        // delete temporary out directory recursively
        Files.walk(tmpDir)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }

    @Test
    public void testCheckForReload_singlepem() throws Exception {
        Path pemFile = tmpDir.resolve("temp.pem");
        Files.copy(
                FileSystems.getDefault().getPath("src/test/resources/pem/single.not-secure.r2.io.pem"),
                pemFile
        );
        touch(pemFile);

        CertificateHolderX509 certHolder = CertificateUtils.loadCertificateX509(
                "pem:"+pemFile.toAbsolutePath().toString(),
                "secret", "server");

        CertificateUtilsTest.checkCertificate_single(certHolder, ReloadablePEMCertificateHolder.class);

        // wait 1.1 second, to avoid file system modification time granularity problems
        Thread.sleep(1100);

        Files.copy(
                FileSystems.getDefault().getPath("src/test/resources/pem/not-secure.r2.io.pem"),
                pemFile, StandardCopyOption.REPLACE_EXISTING
        );
        touch(pemFile);

        ((ReloadablePEMCertificateHolder)certHolder).checkForReload();

        CertificateUtilsTest.checkCertificate_notsecure(certHolder, ReloadablePEMCertificateHolder.class);
    }

    @Test
    public void testCheckForReload_letsencrypt() throws Exception {
        Path fullchain = tmpDir.resolve("fullchain.pem");
        Path privkey = tmpDir.resolve("privkey.pem");
        Files.copy(
                FileSystems.getDefault().getPath("src/test/resources/letsencrypt/single.not-secure.r2.io/fullchain.pem"),
                fullchain
        );
        Files.copy(
                FileSystems.getDefault().getPath("src/test/resources/letsencrypt/single.not-secure.r2.io/privkey.pem"),
                privkey
        );
        touch(fullchain); touch(privkey);

        CertificateHolderX509 certHolder = CertificateUtils.loadCertificateX509(
                "letsencrypt:"+tmpDir.toAbsolutePath().toString(),
                "secret", "server");

        CertificateUtilsTest.checkCertificate_single(certHolder, ReloadablePEMCertificateHolder.class);

        // wait 1.1 second, to avoid file system modification time granularity problems
        Thread.sleep(1100);

        Files.copy(
                FileSystems.getDefault().getPath("src/test/resources/letsencrypt/not-secure.r2.io/fullchain.pem"),
                fullchain, StandardCopyOption.REPLACE_EXISTING
        );
        Files.copy(
                FileSystems.getDefault().getPath("src/test/resources/letsencrypt/not-secure.r2.io/privkey.pem"),
                privkey, StandardCopyOption.REPLACE_EXISTING
        );
        touch(fullchain); touch(privkey);

        ((ReloadablePEMCertificateHolder)certHolder).checkForReload();

        CertificateUtilsTest.checkCertificate_notsecure(certHolder, ReloadablePEMCertificateHolder.class);
    }

    /**
     * Helper method - change file modified time to now by appending a space
     * Looks like copy is keeping the original file dates :(
     */
    public void touch(Path f) throws Exception {
        Files.write(f, new byte[] { 32 }, StandardOpenOption.APPEND);
    }

}