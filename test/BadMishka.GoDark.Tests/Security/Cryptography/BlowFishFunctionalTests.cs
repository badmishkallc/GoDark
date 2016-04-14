using BadMishka.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
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
            var blowFish = BlowFish.Create();
            blowFish.GenerateIV();
            blowFish.GenerateKey();

            var key = blowFish.Key;
            var iv = blowFish.IV;

            var transform = blowFish.CreateEncryptor();
            var testString = "Why I got you on my mind? by Ellie Goulding";
            var inputBuffer = System.Text.Encoding.UTF8.GetBytes(testString);


            byte[] decryptedBytes = EncryptionUtil.CreateOutputBuffer(inputBuffer, blowFish.BlockSize);
            byte[] encryptedBytes = EncryptionUtil.CreateOutputBuffer(inputBuffer, blowFish.BlockSize);
            transform.TransformBlock(inputBuffer, 0, inputBuffer.Length, encryptedBytes, 0);

            Assert.NotEqual(inputBuffer, encryptedBytes);
            Assert.NotEqual(testString, Encoding.UTF8.GetString(encryptedBytes, 0, encryptedBytes.Length));

            blowFish.Padding = System.Security.Cryptography.PaddingMode.None;
            transform = blowFish.CreateDecryptor();
            transform.TransformBlock(encryptedBytes, 0, encryptedBytes.Length, decryptedBytes, 0);

           
            var decrypted = Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length).TrimEnd('\0');
            Assert.Equal(testString, decrypted);

            transform = blowFish.CreateDecryptor();
            decryptedBytes = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            Assert.Equal(inputBuffer, decryptedBytes);
        }
    }
}
