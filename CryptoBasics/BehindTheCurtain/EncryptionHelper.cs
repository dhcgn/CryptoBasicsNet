using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace EncryptionIntro
{
    public class EncryptionHelper
    {
        /// <summary>
        /// Encrypt and return the HMAC
        /// </summary>
        /// <param name="keyHmac"></param>
        /// <param name="keyAes"></param>
        /// <param name="iv"></param>
        /// <param name="pathEncrypted"></param>
        /// <param name="pathPlain"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] keyHmac, byte[] keyAes, byte[] iv, string pathEncrypted, string pathPlain)
        {
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
                        plainStream.CopyTo(aesStream);
                }

                hmacHashData = hmac.Hash;
            }
            var hmacOverall = new HMACSHA512(keyHmac);
            var hmacOverallHash = hmacOverall.ComputeHash(hmacHashData.Concat(iv).Concat(keyAes).Concat(hmacHashData).ToArray());

            return hmacOverallHash;
        }

        /// <summary>
        /// Decrypt and returns the HMAC
        /// </summary>
        /// <param name="keyHmac"></param>
        /// <param name="keyAes"></param>
        /// <param name="iv"></param>
        /// <param name="pathEncrypted"></param>
        /// <param name="pathPlain"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] keyHmac, byte[] keyAes, byte[] iv, string pathEncrypted, string pathPlain)
        {
            byte[] hmacHashData;
            using (var hmac = new HMACSHA512(keyHmac))
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = keyAes;
                    aes.IV = iv;

                    using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (var resultStream = File.OpenWrite(pathPlain))
                    using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    using (var hmacStream = new CryptoStream(aesStream, hmac, CryptoStreamMode.Write))
                    using (var plainStream = File.OpenRead(pathEncrypted))
                        plainStream.CopyTo(hmacStream);
                }

                hmacHashData = hmac.Hash;
            }
            var hmacOverall = new HMACSHA512(keyHmac);
            var hmacOverallHash = hmacOverall.ComputeHash(hmacHashData.Concat(iv).Concat(keyAes).Concat(hmacHashData).ToArray());

            return hmacOverallHash;
        }
    }
}