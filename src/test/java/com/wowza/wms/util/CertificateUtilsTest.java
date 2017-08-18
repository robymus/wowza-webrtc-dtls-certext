package com.wowza.wms.util;

import com.wowza.wms.certificate.CertificateHolderX509;
import io.r2.wowza.webrtc_dtls.ReloadablePEMCertificateHolder;
import io.r2.wowza.webrtc_dtls.SelfSignedCertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

public class CertificateUtilsTest {

    /**
     * Test creating a self signed certificate
     */
    @Test
    public void testLoad_selfsigned() throws Exception {
        CertificateHolderX509 certHolder = CertificateUtils.loadCertificateX509(
                "selfsigned:testdomain.com",
                "secret", "server");
        assertThat(certHolder).isNotNull();
        assertThat(certHolder.getCertificate()).isNotNull().isInstanceOf(X509Certificate.class);
        assertThat(certHolder.getKeyPair()).isNotNull();
        assertThat(certHolder).isInstanceOf(SelfSignedCertificateHolder.class);
        X509Certificate cert = (X509Certificate) certHolder.getCertificate();
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=testdomain.com");
        // should be valid at least 30 days
        assertThat(cert.getNotAfter().getTime()).isGreaterThan(System.currentTimeMillis() + 30*24*3600_000);
    }

    /**
     * Test normal operation (handled by original loader) with jks file
     * @throws Exception
     */
    @Test
    public void testLoad_jks() throws Exception {
        checkCertificate_single(CertificateUtils.loadCertificateX509(
                "src/test/resources/jks/single.not-secure.r2.io.jks",
                "secret", "server"),
                null
        );
    }

    /**
     * Test loading a single pem file
     */
    @Test
    public void testLoad_pem() throws Exception {
        checkCertificate_single(CertificateUtils.loadCertificateX509(
                "pem:src/test/resources/pem/single.not-secure.r2.io.pem",
                "secret", "server"),
                ReloadablePEMCertificateHolder.class
        );
        checkCertificate_notsecure(CertificateUtils.loadCertificateX509(
                "pem:src/test/resources/pem/not-secure.r2.io.pem",
                "secret", "server"),
                ReloadablePEMCertificateHolder.class
        );
    }

    /**
     * Test loading a let's encrypt certificate
     */
    @Test
    public void testLoad_letsencrypt() throws Exception {
        checkCertificate_single(CertificateUtils.loadCertificateX509(
                "letsencrypt:src/test/resources/letsencrypt/single.not-secure.r2.io",
                "secret", "server"),
                ReloadablePEMCertificateHolder.class
        );
        checkCertificate_notsecure(CertificateUtils.loadCertificateX509(
                "letsencrypt:src/test/resources/letsencrypt/not-secure.r2.io",
                "secret", "server"),
                ReloadablePEMCertificateHolder.class
        );
    }

    public static void checkCertificate_single(CertificateHolderX509 certHolder, Class<?> validateClass) throws Exception {
        assertThat(certHolder).isNotNull();
        assertThat(certHolder.getCertificate()).isNotNull().isInstanceOf(X509Certificate.class);
        assertThat(certHolder.getKeyPair()).isNotNull();
        if (validateClass != null) {
            assertThat(certHolder).isInstanceOf(validateClass);
        }
        X509Certificate cert = (X509Certificate) certHolder.getCertificate();
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=single.not-secure.r2.io");
        assertThat(cert.getNotAfter().getTime()).isEqualTo(1496734980000L);
        assertThat(Hex.toHexString(certHolder.getKeyPair().getPrivate().getEncoded()))
                .isEqualTo("30820942020100300d06092a864886f70d01010105000482092c308209280201000282020100e1cfa1c812212a7e5701017526b5ff5878b88f6ed62b5b2fd58a77514c4cc3973ec3bd9cff619a03dc3ad13aadb2642f40eda3d18f478c81db8cb57ebb3da5110e32f0e0cb19535d57786c4764eab83d72101a781a9ac72000a1712f0e13edcff71aaeef56fd81c704e30b045830a6b362c95da3276c07de2daa7bf0915cdb694a4b8a7ad41ead17b5fd729174ad6b3fa73864bad81623e45ff91bbc9990007188de37f76cfbe32557a8093ebb81a5b9dfe426284f941099da343563dab46948260562fccec3c093b6c9c50736246c16805441f6c8180b204fe2051536f3389a5b2237ccd16e88b01fb57699e8f4f019544b966adf2f75cba40c7142b393c885a3474adb2b343f247c3a6c49e915e2fe2c428b8398dced566f6485e88760584819c5a1ad8ecf677450de48081f30e9f16f7f748948a79e5432799a0dd9f5637abdd2a05bffbb8f239d47a9add928c89446084505ba6ae7946ff4f182ab94cc7d346c2a293527efc280dfedf7de20b93f8584d16bd25f5ee6b2ab07ac7a3a254315b745f00ba942190a75addf4e5344986172c711569d87873aebd92cce9dbd93f28b8dc1a559232e33b7e34d99202b094a3e10db2a67a826575016fae7b490602f563164f40a168defde168870a4a7df378baa258eb87e22d6d4f96b7a5322c2a8e11c2624b472aa250307f9e9adc83a1ee8b59f9ec908f05695395f09525b130203010001028202003cb42697b457fa267099329d1dc4fb59fb4a1235079a2c2f55c69d80db741f787f44fbaa42f5280435a6122d2618b8da03285f4bacaadd58e37e9623f58e02dbece740de0d7b476fe65dd72df2312f4a456992d40ac2e518f352732ce529f25a5fe16a79a8f709764918081428e91b474a1d3bf0ea5e1e575a0b64ba2d39bb3a38e0c9df6f3ab7e991e10a7593da32e4afbd7746cb64584dc287232fb65081ee038f49985851f6a449464105fe3e42210fd13378cebbcd22af082dfa24072fee575a475c12f188c9acefdce9ad6269343b576b4c3e4a48636d56236baa9403f96ada6e09bf9b695f7f86b6d5754cb366fbc43e3188c2277691294f2151493f343c7aca349eaf5b324817b7ce00caa3935785f4506f5b7bc94143b77cd8fa0bd940623a0701185ac110157d7794ce828ad5f5fdefab66320685d8155678fdcf6b6529618a2d2a984a8fe25d765faa37a1f2791b090fcc9ad723b0030a8ca882e38ba3f517a7cd1cfd4cc3ab9627908f80e2c3ed068ddf10a1f058f5b1704b1da2266ca5464c3067ea196b09d4c2a6c2a97905cef8154ff1da097172f5af12b4bb0faf55cb30d49e44a644a239d8df7dd0d0552ba15367417bc3daa019faf8ce2146045a082c50438b9436ca9ce4e7aada7fbfae90e03b5985ea03d98ece7ce97301a54e525b1bc89028ddbbbf17108ab4dd3bfd37bbf0ffcf37ab96fbb3022fe10282010100f6997c8d610f7321e22738d9f69dde0f7d86170892e2dd48e3ae625588e793d6733b92aa5cdb3c3cfebf441383677e41ee529c58324e4638c17b6dfb00be30a3a6f2abdbc0c8388790659038067e6700128c423f7fa2e9980699dde1398c807f0c74f24d9b83b008dc9d39ad14146782c6e0ef19c33044e04efad16d96d6ffefef152867b0f92d48aae023e01ce0ddc356fc1f921316deb8484d2091a73a2cff25a4865d0b1282f973824268dd9a24dd6f763fe3653e8621b558352e0aa0d368c52804ff2b1d1ee817bd7ec3be8d8dd662b22aa8a946a765b177a00ddf1d4948b6e383559d5962945307af8e28f42c7369da95e0853195a4099273e7d82fb4d90282010100ea6b465d3cbb7b1becaaba3a256ecd317a6fad7e321f372125938b9373c75daa2bd24c7cf1f869f7b904cf0c6f4af4b083b1042a8ee592a040be1337de1f731b2467f384f18ca4dac30676e908bd65bb7613cdf7bcdd2b1f293ae53636ca50dfcefcd0fca13724490feb0cf5db114d62dac2759fee259ed1eb72fab8f9773a67a361a209b6a08fa5f4284f17be2b09924aba6cd2fc26bd9660379b2dffe39c787d1fad3ccf0dc422e642d0a9c05b77f100e8b6ce3a094c498be048f56adaefc3a79793e079e6e5488fb39283493343f7a5c491c25eb6b7a771a75856c6b812d8254ee1ad0634ad82b1160b31809f1436e260d35940b2828d51797a0fe899abcb028201006898d5e1c9e799b8278ae76c5c54bdd9e82e361ae6e2df65895d704c4393a67b71c934fe9a004bdebb573972e56bc27c08b075ac5b3a2442f29e7e19d748d4acb5a57d0beb0b821ece3aa61f7d71a412bdcb4c564eb73549cc92fb300b0ef379f038b286048ea8de39655f0f70d2eecce3ba88f06e804cd6afe967678a718b81a3f15f800beac5306b7a42fd4e827acdde5976b2a8f22c6a1210d4ddb306d40b2d5649bfb1709aa9603b421be4d2fb0c09b92884356f7dc9527825a66fcfa39c6ef3f89a9b18f1011500c58215934934440cba576be5921f6a55094898f87d1b20a8040f0e7cd9797c76681a6e78935a28ee1460755e80d06157035eb5ae16910282010045e827dbb638d2c5c91640e30636bcca7c90c15458ee262aa46213c5ad494f0d6874168b4c3da09c5778afa62daa54be2f07a30e6dfed87321db8d2fa3f60d05931dcce9607f68ca344ec1374d7bedd2b1abc64892f201e2111197394bad99e0a481907146428377a65f9a45d74699a55947947c5530b2e4372adaca3edae777f0a93501608d1149943e5117eb863a1c7e5c8a07815aac3f2402712c8e9afa169479d5d7c4877e6e49ecb2fd6c77da94ec8879bb96631f74ef59bb6834ad85c2fb3fa0c1d8989ad7c0c2f4766265ff66e2f073e75b07724d64ff5ac0c6122ecc7693c78929c89bd5d5a9953cf5f67ab8c359ccad5935e2e8f1db20238e6205710282010100b8f987363f8df7e8331263a669ef7bcb0c18e55d68374b49b7010d3cbc9ffbddc57c7631f57ef6b40a8e6cdb97cd55d9f16f39826084217c41169fbe8261634c65fe33e36afea4ba56a7cebf98da6a596c00d41d00f4db548882e005c21fe17b879e03757cb54a8677f6058f9e34f210449ff4d56a856259e9ee0ce3ad896499f5deef06ad66be0c53bb9c1fae97ca1c808e29872d9ba58a7108fbf428230bf064d4b916916ba53bbd28bd485e617d8491720adc34182060a308d8f6627003d7c201ba433ef7cd6c03a088ae952731ec3e86021de634ace6d796b5ef48bf142881029e6273adf3e1a8540a902da51676f0303b4039b1acfeb42528f12dacb224");
    }

    public static void checkCertificate_notsecure(CertificateHolderX509 certHolder, Class<?> validateClass) throws Exception {
        assertThat(certHolder).isNotNull();
        assertThat(certHolder.getCertificate()).isNotNull().isInstanceOf(X509Certificate.class);
        assertThat(certHolder.getKeyPair()).isNotNull();
        if (validateClass != null) {
            assertThat(certHolder).isInstanceOf(validateClass);
        }
        X509Certificate cert = (X509Certificate) certHolder.getCertificate();
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=not-secure.r2.io");
        assertThat(cert.getNotAfter().getTime()).isEqualTo(1496734680000L);
        assertThat(Hex.toHexString(certHolder.getKeyPair().getPrivate().getEncoded()))
                .isEqualTo("30820944020100300d06092a864886f70d01010105000482092e3082092a0201000282020100ca34784e505dd921cdbb40a3eb6937f9cdd3fde13876cb33150e9632f2b6cd4ca3baba56d448a8c6d2f7e76e51e7b11c6f37c337632adae8f611ce0ef8cb399cd2148d37bf7fa2024d79a06903001d8ca883558d6108e442c507f67522c1707188274b8e38f37c5497fdc894dfadee3139f68545a40b2dcd51115f7877e166ccf7e475b79a5f31f97de8cf22d338d0e4c219fd1b961781be3b71ac5f1c219cb67cb91f89141ae517fde914c888d99243a9fd449b7cf74ea2d65545ce7fe0debe564b18ef56874a93a5c8b62b545b97d3b4f1bf555c7f7a759900e5fca3d2b956a14e3d0d5b95dbb9f7a3b95de73b28550383a4b73d43219092815283f2f7c1484ad8ef9d24d4194480958ef730e7a3a60b55062c52796fa82ebfdf8b1774ea324a96a59499859d6a85d172f0bc02add8050bd7f3bc49b57e33f79b561b5151f31c4d82dd10f7079d628a3d2ba00a62d7d07fa626967aa337bff7acd1436cb159145502f61f3265aca0f6fee33700ef5aa0427d4f99f9ba672a39fbe444f20a7d9b9ae9f48e9004635d65c658fc56593787bbd624a51db828f86170432e4d349636ca92a71cbedd823599d2af67bbaaaaa3f5b1b89ab470e4aa53c8b3d5f03acc93d3fde254dde752a7376e8009fdf5ceaafc5d3d1ddfd0b048db477292b0450be0b3ad3ec03f1eb69c923b7c44cf562a107c37f6d34bc4a626628d203642a0f70203010001028202010082f3a63239b3fda9f9bdda680e4e6f34f58ae43196cac0604db3cbac252a241d0d3021fb97b192b468eea9cff575526b72cfaf3ad09b71784bdc4e11be2887203ba199af4ff2cdae2614adc134733fafd7766ed287d42557e4987a9173b7c9258da2bd38d74340f2dc183c6dc5cab3a6e7bdf2a39e50ab11fbfd7f51da797c8523c9ae3f00d7c3daab2339fa78c6a3ea729638284474e6ce975acfe22caacbfe171a21053aa30c5914547de43d54827815bff34dab89d2407d046e980493524dfc3ed860302ea02aacc426ce3aecb29025f026149739ebc9fb13ecde480e717f5c29fa3a0b652b0eee04f7488c36f0b0d5fccc90eb38eda4de6ca84ed1ec881c2cba3a67e6d0dcbc8121bf99b21873e87f7ba4df01d0bcac56bcd2bb3caa69d24e04434a6d6d9cb120b4694bd532c0e9f58fd6250b4e7f279d597033ea97206763e56d301d630f052ae3143bfc840edc9da4f87c0bc171a8ca78524d85fb995fd5c344c0a23b801d8bcfcd61ee2f72a2433f0bc58bfb00874ab37349796b161586ea4d159bd3118d1ba6d159f2a2660c31632f75e4ea4ac9be5249b53024b0a8fa4dd814ffb14cdf69469e3d18556f5092a08421e027794001012ff780962389c68e4d8a67755b0199a8cb2618665ae76176997f8ca84a58a83efe1557e1b5411f6bf5760ede96ecd78b795ed1379c0035de8ec2940b25a895bf221115d9ee790282010100f7673063697b277bcff2bf8c7d92e37a0ba1ed13c418746023532010e5841c7f0fedd3c41eb9beb4b663955dd57db6a68c7919ed3c216a74cc74fe01ea21a1833bb66299a6e35134f1be640ff89a0bc6f247ef6f686e9372811027d9260e7e703deadbd443c724c9613aac34a1f91c52e79423d4d4a33e3dc8c79eff81392109b5c018383634877a35d372cce771b87e160fdab23a6336aeb2d9237bc1a21a644fd28a4f16d12a9327f43e3ebf72e12e0258681086743e52a535b97aef1b33c43e443652ec1fdf3a8a3894687e98e6d14393f77dacb5e5045c4736aefb6252e585c7c4c33cac0613da9562fd24acc8376d9201d7cac0993e89649ce5438a9a650282010100d13b36dca4fee5253ef7f5cfb84b4fa8898eb37bbc685c7fa440c33770d59db6d95db3300bdcd2f9677ba75f4a7be19d25032c6611a30403853d5fd0f82fee35b1cac7c214b76b9724dcdccfa083a6ac547852db207aa30350faff336d8d337c667924f4970378a96b121a7e360f79389a351b9c1435c2a9d8c27e34ea1aa9d0c13088dcbc48ffae64b0bff473ecd845a3ee5643b9503972a41579cee60803baa9d24742b6fdac5dfadbae2c350453038449c368907e75a2118f3b1c3643c2dea7b9500ba15e5c7eb1ed060b88416f19699d90ffe9bfb429b4357ff15d7db8b634879f015457d6399c9b9abcb157f81c854e9c252e4772c5c0979e80219bca2b0282010100957f835bef377e2a71042cff863a26bf6f1c1018ab9c63665cb23464416ccd93725ab2668672936cbbf1fd265085c0c36f8b1641a6de426805cc84593fd3c6b77873c3ad398d8f5ac0e1ddb150f6353ba8d813356d13b481b2bfc274936c9ab6d49380f70965e332d550111354f5254a6ba9b6e53b00d1f19fcc10a630be06dac93b24e782c9c73bf01eaff665bcf051309faff59716b0ca6c448e0e9079961d1ba70bf0b2c6fe452215932f739cc5b979ad5664f5fa74569882986c52e44b29c0be935d1456461c27bdfce00feff13a6eed90d61e7163cc78be87aac1392f02870eaa35980a133a1811c1595aba15da78998c078bfb4a1ee2032c53d5b68189028201003ec7559ebea2fc7e407685fadd813b5586709ac9f5ae1a92f1e5bcad55ddc284aa93c2c017cf1a3e5b1e6f09d87f732283888039dff0d9b374b70598dddf03ca789e2f71bc658c92bd2cc7d444853bed592b01315e7d6d8c01304e824fcc9e362549141d8f722b322a3e3454ca43ba4b91797ddf46f11a877bd25fabe0d23f41b3b5ac5b0ee39853eb425d562bb254f2104de2f44f161326a2b50ee7557df2207ff3e80dcc7a30cdc207482b5b7d00ab7d75e47beb5f064caa981f5447b3ed34817ec8d5b4856b9b58279638bf99628c6d74299d9fb535898dd8bf9adc426cb9bee9327c63a23754f1f87e653f90f591192e8d0b5ae7753880a0fd9dd477ba210282010100de685f6986942f57315f9782ae3dbf0d91ee389ac953bde83a965d41b2dd1343237a1be92d2ec3c7381a9a14ef9624b727fc27700c2f2a320628f9fe916a4375ec470ee52daf10d33bf387b359fe49bf17c4287b17ca4919f2e4de02e182ffc11bc745055780fd297737ea37283d6b38a02bb8b984038977c937f98aeb5cd8eddcb3d29886fe80d3ec7caefb76feea84d55af155d398d50d167614a8b618cd9944261ca83de3b1880dae98891fe473098393710c04033fe1e5b1a32aaee18377f0d7c037f0b660dd38846a476b183d5f8e2c1a04c0d03b98a6d65f418131a7f49cf75430f88a50397fc793f380a23c4150cf67517596c428dec8b91733cd58e5");
    }


}