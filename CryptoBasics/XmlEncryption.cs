using System.Xml;
using NUnit.Framework;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace EncryptionIntro
{
    [TestFixture]
    public class XmlEncryption
    {
        [Test]
        public void Test1()
        {
            var xmlString = @"
<bookstore>
  <book genre=""fantasy""  ISBN=""2-3631-4"">
    <title>Oberon's Legacy</title>
    <author>Corets, Eva</author>
    <price>5.95</price>
    <secret>this is a secret</secret>
  </book>
</bookstore>";

            var doc = new XmlDocument();
            doc.LoadXml(xmlString);

            XmlElement root = doc.DocumentElement;
            var temp = root.GetElementsByTagName("secret")[0] as XmlElement;
            

            var encXml = new EncryptedXml();
            encXml.Encrypt(temp, new X509Certificate2());
            
        }
    }
}