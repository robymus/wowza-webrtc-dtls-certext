package com.wowza.wms.util;

import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This test checks if the class signature of CertificateUtils and CertificateUtils0 (original) are the same
 * When compiling with newer versions of wowza libraries, this ensures that compatibility is not broken
 */
@Test
public class CheckClassSignatureTest {

    @Test
    void checkSignature() {
        Set<String> methodList0 = Arrays.stream(CertificateUtils0.class.getMethods())
                .map(m -> m.toString().replaceAll("CertificateUtils0", "CertificateUtils"))
                .collect(Collectors.toSet());
        Set<String> methodList1 = Arrays.stream(CertificateUtils.class.getMethods())
                .map(m -> m.toString())
                .collect(Collectors.toSet());
        assertThat(methodList1).isEqualTo(methodList0);
    }
}