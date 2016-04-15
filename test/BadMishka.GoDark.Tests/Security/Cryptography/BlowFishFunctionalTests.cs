using BadMishka.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BadMishka.GoDark.Tests.Security.Cryptography
{
    public class BlowFishFunctionalTests
    {

        [Fact]
        public static void Encrypt_And_Decrypt()
        {
            var utf8 = new UTF8Encoding(false, false);
            var blowFish = BlowFish.Create();
            blowFish.Mode = CipherMode.CBC;
            blowFish.GenerateIV();
            blowFish.GenerateKey();

            var key = blowFish.Key;
            var iv = blowFish.IV;

            var transform = blowFish.CreateEncryptor();
            var testString = "Why I got you on my mind? by Ellie Goulding";

            var ms1 = new MemoryStream();
            using (var cryptoStream = new CryptoStream(ms1, blowFish.CreateEncryptor(key, iv), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cryptoStream))
            {
                sw.Write(testString);
            }

            var encryptedBytes = ms1.ToArray();
            ms1.Dispose();

            Assert.NotEqual(testString, utf8.GetString(encryptedBytes));

            string decryptedString = null;

            using (var ms = new MemoryStream(encryptedBytes))
            using (var cryptoStream = new CryptoStream(ms, blowFish.CreateDecryptor(key, iv), CryptoStreamMode.Read))
            using (var sr = new StreamReader(cryptoStream))
            {
                decryptedString = sr.ReadToEnd();
            }

            Assert.NotNull(decryptedString);
            Assert.Equal(testString, decryptedString);
        }
    }
}
