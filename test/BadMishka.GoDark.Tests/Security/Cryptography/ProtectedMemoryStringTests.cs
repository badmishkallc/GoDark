using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BadMishka.Security.Cryptography
{
    public class ProtectedMemoryStringTests
    {

        public class Constructor
        {
            [Fact]
            public static void EncryptsValue()
            {
                var bytes = Encoding.UTF8.GetBytes("galvatron password");
                var protectedMemoryString = new ProtectedMemoryString(bytes);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var internalText = typeof(ProtectedMemoryString).GetRuntimeFields().SingleOrDefault(o => o.Name == "text");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryString);
                var plainText = internalText.GetValue(protectedMemoryString) as string;

                Assert.Null(plainText);

                Assert.NotEmpty(encryptedBytes);
                Assert.NotEqual(bytes, encryptedBytes);

                Assert.Equal(protectedMemoryString.Length, bytes.Length);

                Assert.NotEqual(new byte[8], protectedMemoryString.Id);
            }

            [Fact]
            public static void StoresValueInMemory()
            {
                var bytes = Encoding.UTF8.GetBytes("galvatron2 password");
                var protectedMemoryString = new ProtectedMemoryString(bytes, false);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var internalText = typeof(ProtectedMemoryString).GetRuntimeFields().SingleOrDefault(o => o.Name == "text");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryString);
                var plainText = internalText.GetValue(protectedMemoryString) as string;

                Assert.Null(plainText);

                var copy = new byte[bytes.Length];
                Array.Copy(encryptedBytes, copy, bytes.Length);

                Assert.NotEmpty(copy);
                Assert.Equal(bytes, copy);
                Assert.Equal(protectedMemoryString.Length, bytes.Length);
                if (!(bytes.Length % 16 == 0))
                    Assert.NotEqual(encryptedBytes.Length, bytes.Length);

                Assert.NotEqual(new byte[8], protectedMemoryString.Id);
            }

            [Fact]
            public static void StoresStringInMemory()
            {
                var expectedText = "galvatron2 password";
                var protectedMemoryString = new ProtectedMemoryString(expectedText);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var internalText = typeof(ProtectedMemoryString).GetRuntimeFields().SingleOrDefault(o => o.Name == "text");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryString);
                var plainText = internalText.GetValue(protectedMemoryString) as string;

                Assert.Null(encryptedBytes);
                Assert.NotNull(plainText);
                Assert.Equal(expectedText, plainText);
            }
        }

        public class Unprotect
        {

            [Fact]
            public static void ReturnsUnprotectedString()
            {
                var expectedText = "megatron45 password";
                var bytes = Encoding.UTF8.GetBytes("megatron45 password");
                var protectedMemoryString = new ProtectedMemoryString(bytes);

                Assert.Equal(expectedText, protectedMemoryString.Unprotect());
            }
        }

        public class UnprotectAndCopyData
        {
            [Fact]
            public static void ReturnsDecyptedData()
            {
                var bytes = Encoding.UTF8.GetBytes("megatron3 password");
                var protectedMemoryString = new ProtectedMemoryString(bytes);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryString);
                var copy = new byte[bytes.Length];
                Array.Copy(encryptedBytes, copy, bytes.Length);

                Assert.NotEmpty(copy);
                Assert.NotEqual(bytes, copy);

                var decryptedBytes = protectedMemoryString.UnprotectAndCopyData();
                Assert.Equal(bytes, decryptedBytes);
            }

            [Fact]
            public static void ReturnsStringAsBytes()
            {
                var bytes = Encoding.UTF8.GetBytes("megatron5 password");
                var protectedMemoryString = new ProtectedMemoryString("megatron5 password");

                Assert.Equal(bytes, protectedMemoryString.UnprotectAndCopyData());
            }

        }
    }
}
