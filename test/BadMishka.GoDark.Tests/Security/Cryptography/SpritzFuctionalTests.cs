using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BadMishka.Security.Cryptography
{
    public class SpritzFunctionalTests
    {

        [Fact]
        public static void Encrypt_And_Decrypt()
        {
            var spritz = Spritz.Create();
            spritz.GenerateIV();
            spritz.GenerateKey();

            var key = spritz.Key;
            var iv = spritz.IV;

            var transform = spritz.CreateEncryptor();
            var testString = "how like me now by The Heavy";
            var inputBuffer = System.Text.Encoding.UTF8.GetBytes(testString);
            byte[] decryptedBytes = new byte[inputBuffer.Length];
            byte[] encryptedBytes = new byte[inputBuffer.Length];
            transform.TransformBlock(inputBuffer, 0, inputBuffer.Length, encryptedBytes, 0);

            Assert.NotEqual(inputBuffer, encryptedBytes);
            Assert.NotEqual(testString, Encoding.UTF8.GetString(encryptedBytes, 0, encryptedBytes.Length));

            transform = spritz.CreateDecryptor();
            transform.TransformBlock(encryptedBytes, 0, encryptedBytes.Length, decryptedBytes, 0);

            Assert.Equal(inputBuffer, decryptedBytes);
            Assert.Equal(testString, Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length));
        }
    }
}
