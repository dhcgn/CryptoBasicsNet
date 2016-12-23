using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace EncryptionIntro
{
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