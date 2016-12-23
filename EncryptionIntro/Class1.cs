using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

// ReSharper disable ConvertToConstant.Local

namespace EncryptionIntro
{
    [TestFixture]
    public class Encryption
    {
        [Test]
        public static void EncryptionWithHmac()
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
        public static void Encryption()
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

    public class TestConstants
    {
        public static byte[] GetRandomData(int bits)
        {
            var randomBase64Date = "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";
            return Convert.FromBase64String(randomBase64Date).Take(bits / 8).ToArray();
        }
    }

    [TestFixture]
    public class Hashing
    {
        

        [Test]
        public static void Authenticate()
        {
            var encryptedData = TestConstants.GetRandomData(512);

            var hmac = new HMACSHA512
            {
                Key = TestConstants.GetRandomData(512)
            };
            hmac.ComputeHash(encryptedData);

            Console.Out.WriteLine($"Hash: {BitConverter.ToString(hmac.Hash, 0, 16)}...");
            // Hash: 1F-FA-7E-99-CF-21-72-26-50-4F-1D-51-66-F5-73-A2...

            Assert.That(hmac.HashSize, Is.EqualTo(512));
            Assert.That(BitConverter.ToString(hmac.Hash, 0, 16),
                Is.EqualTo("1F-FA-7E-99-CF-21-72-26-50-4F-1D-51-66-F5-73-A2"));
        }


     

        [Test]
        public static void HashSampleFile()
        {
            var path = Path.GetTempFileName();
            File.WriteAllText(path, "Hello World");

            byte[] hash;
            using (var stream = File.OpenRead(path))
            {
                hash = SHA512.Create().ComputeHash(stream);
            }

            File.Delete(path);

            Console.Out.WriteLine($"Hash: {BitConverter.ToString(hash, 0, 16)}...");
            // Hash: 2C-74-FD-17-ED-AF-D8-0E-84-47-B0-D4-67-41-EE-24...

            Assert.That(BitConverter.ToString(hash, 0, 16),
                Is.EqualTo("2C-74-FD-17-ED-AF-D8-0E-84-47-B0-D4-67-41-EE-24"));
        }

        [Test]
        public static void HashSampleString()
        {
            var text = "Hello World";
            var buffer = Encoding.UTF8.GetBytes(text);

            var hash = SHA512.Create().ComputeHash(buffer);

            Console.Out.WriteLine($"Hash: {BitConverter.ToString(hash, 0, 16)}...");
            // Hash: 2C-74-FD-17-ED-AF-D8-0E-84-47-B0-D4-67-41-EE-24...

            Assert.That(BitConverter.ToString(hash, 0, 16),
                Is.EqualTo("2C-74-FD-17-ED-AF-D8-0E-84-47-B0-D4-67-41-EE-24"));
        }

        [Test]
        public static void KeyDerivation()
        {
            var text = "Hello World";
            var buffer = Encoding.UTF8.GetBytes(text);

            var salt = TestConstants.GetRandomData(128);
            var iterations = 10000;
            var keyLength = 64;

            byte[] hash;
            using (var pbkdf2 = new Rfc2898DeriveBytes(buffer, salt, iterations))
            {
                hash = pbkdf2.GetBytes(keyLength);
            }

            Console.Out.WriteLine($"Hash: {BitConverter.ToString(hash, 0, 16)}...");
            // Hash: 69-83-50-CF-59-F8-B3-36-18-55-06-DD-32-EC-3D-78...

            Assert.That(BitConverter.ToString(hash, 0, 16),
                Is.EqualTo("72-72-49-D5-2D-F4-4E-A1-B0-FD-F9-7F-BA-76-AB-04"));
        }
    }
}