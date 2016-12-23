using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

namespace EncryptionIntro
{
    [TestFixture]
    public class Encryption
    {
        [Test]
        public static void EncryptionWithHmacSymmetric()
        {
            var pathPlain = Path.GetTempFileName();
            var pathEncrypted = Path.GetTempFileName();

            File.WriteAllText(pathPlain, "Hello World");

            var iv = TestConstants.GetRandomData(128);
            var keyAes = TestConstants.GetRandomData(256);
            var keyHmac = TestConstants.GetRandomData(512);

            byte[] hmacHashData;
            using (var hmac = new HMACSHA512(keyHmac))
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = keyAes;
                    aes.IV = iv;

                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (var resultStream = File.OpenWrite(pathEncrypted))
                    using (var hmacStream = new CryptoStream(resultStream, hmac, CryptoStreamMode.Write))
                    using (var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                    using (var plainStream = File.OpenRead(pathPlain))
                    {
                        plainStream.CopyTo(aesStream);
                    }
                }

                hmacHashData = hmac.Hash;
            }
            var hmacOverall = new HMACSHA512(keyHmac);
            var hmacOverallHash = hmacOverall.ComputeHash(hmacHashData.Concat(iv).Concat(keyAes).Concat(hmacHashData).ToArray());

            Console.Out.WriteLine($"HMACSHA512:      {BitConverter.ToString(hmacOverallHash, 0, 16)}...");
            // HMACSHA512: CD-D3-DC-66-74-CD-D6-2E-25-D4-13-2E-99-E6-45-64...
            Console.Out.WriteLine($"Encrypted Bytes: {BitConverter.ToString(File.ReadAllBytes(pathEncrypted), 0, 16)}...");
            // Encrypted Bytes: 40-8D-1B-1B-B0-72-35-12-89-90-97-A8-7D-F7-D4-BD...

            Assert.That(BitConverter.ToString(hmacOverallHash, 0, 16),
                Is.EqualTo("CD-D3-DC-66-74-CD-D6-2E-25-D4-13-2E-99-E6-45-64"));

            Assert.That(BitConverter.ToString(File.ReadAllBytes(pathEncrypted), 0, 16),
                Is.EqualTo("40-8D-1B-1B-B0-72-35-12-89-90-97-A8-7D-F7-D4-BD"));

            File.Delete(pathPlain);
            File.Delete(pathEncrypted);
        }

        [Test]
        public static void EncryptionAndDecryptionWithHmacSymmetric()
        {
            var pathPlain = Path.GetTempFileName();
            var pathEncrypted = Path.GetTempFileName();
            var pathDecrypted = Path.GetTempFileName();

            File.WriteAllText(pathPlain, "Hello World");

            var iv = TestConstants.GetRandomData(128);
            var keyAes = TestConstants.GetRandomData(256);
            var keyHmac = TestConstants.GetRandomData(512);

            var hmacOverallHash1 = EncryptionHelper.Encrypt(keyHmac, keyAes, iv, pathEncrypted, pathPlain);
            var hmacOverallHash2 = EncryptionHelper.Decrypt(keyHmac, keyAes, iv, pathEncrypted, pathDecrypted);

            Assert.That(hmacOverallHash1, Is.EqualTo(hmacOverallHash2));
            Assert.That(File.ReadAllBytes(pathPlain), Is.EqualTo(File.ReadAllBytes(pathDecrypted)));

            File.Delete(pathPlain);
            File.Delete(pathEncrypted);
            File.Delete(pathDecrypted);
        }

        [Test]
        public static void EncryptSymmetric()
        {
            var pathPlain = Path.GetTempFileName();
            var pathEncrypted = Path.GetTempFileName();

            File.WriteAllText(pathPlain, "Hello World");

            var iv = TestConstants.GetRandomData(128);
            var keyAes = TestConstants.GetRandomData(256);

            using (var aes = Aes.Create())
            {
                aes.Key = keyAes;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var resultStream = File.OpenWrite(pathEncrypted))
                using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                using (var plainStream = File.OpenRead(pathPlain))
                {
                    plainStream.CopyTo(aesStream);
                }
            }

            Console.Out.WriteLine($"Encrypted Bytes: {BitConverter.ToString(File.ReadAllBytes(pathEncrypted), 0, 16)}...");
            // Encrypted Bytes: 40-8D-1B-1B-B0-72-35-12-89-90-97-A8-7D-F7-D4-BD...

            Assert.That(BitConverter.ToString(File.ReadAllBytes(pathEncrypted), 0, 16),
                Is.EqualTo("40-8D-1B-1B-B0-72-35-12-89-90-97-A8-7D-F7-D4-BD"));

            File.Delete(pathPlain);
            File.Delete(pathEncrypted);
        }
    }
}