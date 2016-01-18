using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BadMishka.Security.Cryptography
{
    public class ProtectedMemoryBinaryTests
    {

        public class Constructor
        {

            [Fact]
            public static void EncryptsValue()
            {
                var bytes = Encoding.UTF8.GetBytes("megatron password");
                var protectedMemoryBinary = new ProtectedMemoryBinary(bytes);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryBinary);

                Assert.NotEmpty(encryptedBytes);
                Assert.NotEqual(bytes, encryptedBytes);
               
                Assert.Equal(protectedMemoryBinary.Length, bytes.Length);

                Assert.NotEqual(new byte[8], protectedMemoryBinary.Id);
            }

            [Fact]
            public static void StoresValueInMemory()
            {
                var bytes = Encoding.UTF8.GetBytes("megatron2 password");
                var protectedMemoryBinary = new ProtectedMemoryBinary(bytes, false);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryBinary);
                var copy = new byte[bytes.Length];
                Array.Copy(encryptedBytes, copy, bytes.Length);

                Assert.NotEmpty(copy);
                Assert.Equal(bytes, copy);
                Assert.Equal(protectedMemoryBinary.Length, bytes.Length);
                if (!(bytes.Length % 16 == 0))
                    Assert.NotEqual(encryptedBytes.Length, bytes.Length);

                Assert.NotEqual(new byte[8], protectedMemoryBinary.Id);
            }
        }


        public class UnprotectAndCopyData
        {

            [Fact]
            public static void ReturnsDecyptedData()
            {
                var bytes = Encoding.UTF8.GetBytes("megatron3 password");
                var protectedMemoryBinary = new ProtectedMemoryBinary(bytes);

                var internalBinary = typeof(ProtectedMemoryBinary).GetRuntimeFields().SingleOrDefault(o => o.Name == "binary");
                var encryptedBytes = (byte[])internalBinary.GetValue(protectedMemoryBinary);
                var copy = new byte[bytes.Length];
                Array.Copy(encryptedBytes, copy, bytes.Length);

                Assert.NotEmpty(copy);
                Assert.NotEqual(bytes, copy);

                var decryptedBytes = protectedMemoryBinary.UnprotectAndCopyData();
                Assert.Equal(bytes, decryptedBytes);
            }
        }
    }
}
