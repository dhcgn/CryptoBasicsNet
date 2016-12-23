using System.Security.Cryptography;
using NUnit.Framework;

namespace EncryptionIntro
{
    [TestFixture]
    public class EllipticCurve
    {
        [Test]
        public void DH_DeriveKeyMaterial_DhCreate()
        {
            var alice = ECDiffieHellman.Create(); // soon with different curves!
            var bob = ECDiffieHellman.Create();

            Assert.That(alice.PublicKey.ToXmlString(),
                Is.Not.EqualTo(bob.PublicKey.ToXmlString()));

            var aliceSharedSecret = alice.DeriveKeyMaterial(bob.PublicKey);
            var bobSharedSecret = bob.DeriveKeyMaterial(alice.PublicKey);

            Assert.That(aliceSharedSecret, Is.EqualTo(bobSharedSecret));
        }


        [Test]
        public void DH_DeriveKeyMaterial_DhCgn()
        {
            var alice = new ECDiffieHellmanCng(); // soon with different curves!
            var bob = new ECDiffieHellmanCng();

            Assert.That(alice.PublicKey.ToXmlString(),
                Is.Not.EqualTo(bob.PublicKey.ToXmlString()));

            var aliceSharedSecret = alice.DeriveKeyMaterial(bob.PublicKey);
            var bobSharedSecret = bob.DeriveKeyMaterial(alice.PublicKey);

            Assert.That(aliceSharedSecret, Is.EqualTo(bobSharedSecret));
        }


        [Test]
        public void DH_DeriveKeyMaterial_CgnKey()
        {
            var alice = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, null, new CngKeyCreationParameters {ExportPolicy = CngExportPolicies.AllowPlaintextExport});
            var bob = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, null, new CngKeyCreationParameters {ExportPolicy = CngExportPolicies.AllowPlaintextExport});

            var alicePublic = alice.Export(CngKeyBlobFormat.EccPublicBlob);
            var bobPublic = bob.Export(CngKeyBlobFormat.EccPublicBlob);

            Assert.That(alicePublic, Is.Not.EqualTo(bobPublic));

            var alicePrivate = alice.Export(CngKeyBlobFormat.EccPrivateBlob);
            var bobPrivate = bob.Export(CngKeyBlobFormat.EccPrivateBlob);

            Assert.That(alicePrivate, Is.Not.EqualTo(bobPrivate));

            var aliceSharedSecret = new ECDiffieHellmanCng(alice).DeriveKeyMaterial(CngKey.Import(bobPublic, CngKeyBlobFormat.EccPublicBlob));
            var bobSharedSecret = new ECDiffieHellmanCng(bob).DeriveKeyMaterial(CngKey.Import(alicePublic, CngKeyBlobFormat.EccPublicBlob));

            Assert.That(aliceSharedSecret, Is.EqualTo(bobSharedSecret));
        }


        [Test]
        public void ECDsa_SignData()
        {
            var alicePrivate = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, null, new CngKeyCreationParameters {ExportPolicy = CngExportPolicies.AllowPlaintextExport});
            var alicePublic = CngKey.Import(alicePrivate.Export(CngKeyBlobFormat.EccPublicBlob), CngKeyBlobFormat.EccPublicBlob);

            var data = TestConstants.GetRandomData(1024);
            var sign = new ECDsaCng(alicePrivate).SignData(data, HashAlgorithmName.SHA512);

            var verfiy = new ECDsaCng(alicePublic).VerifyData(data, sign, HashAlgorithmName.SHA512);

            Assert.That(verfiy, Is.True);
        }

        [Test]
        public void ECDsa_SignHash()
        {
            var alicePrivate = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, null, new CngKeyCreationParameters {ExportPolicy = CngExportPolicies.AllowPlaintextExport});
            var alicePublic = CngKey.Import(alicePrivate.Export(CngKeyBlobFormat.EccPublicBlob), CngKeyBlobFormat.EccPublicBlob);

            var data = TestConstants.GetRandomData(1024);
            var sign = new ECDsaCng(alicePrivate).SignHash(data);

            var verfiy = new ECDsaCng(alicePublic).VerifyHash(data, sign);

            Assert.That(verfiy, Is.True);
        }
    }
}