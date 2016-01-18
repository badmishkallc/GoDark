using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BadMishka.Security.Cryptography
{
    public class Salsa20FunctionalTests
    {

        [Fact]
        public static void Encrypt_And_Decrypt()
        {
            var salsa = Salsa20.Create();
            salsa.GenerateIV();
            salsa.GenerateKey();

            var key = salsa.Key;
            var iv = salsa.IV;

            var transform = salsa.CreateEncryptor();
            var testString = "Why I got you on my mind by Ellie Goulding";
            var inputBuffer = System.Text.Encoding.UTF8.GetBytes(testString);
            byte[] decryptedBytes = new byte[inputBuffer.Length];
            byte[] encryptedBytes = new byte[inputBuffer.Length];
            transform.TransformBlock(inputBuffer, 0, inputBuffer.Length, encryptedBytes, 0);

            Assert.NotEqual(inputBuffer, encryptedBytes);
            Assert.NotEqual(testString, Encoding.UTF8.GetString(encryptedBytes, 0, encryptedBytes.Length));

            transform = salsa.CreateDecryptor();
            transform.TransformBlock(encryptedBytes, 0, encryptedBytes.Length, decryptedBytes, 0);

            Assert.Equal(inputBuffer, decryptedBytes);
            Assert.Equal(testString, Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length));
        }
    }
}
