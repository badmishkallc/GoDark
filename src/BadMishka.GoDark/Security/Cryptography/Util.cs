using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace BadMishka.Security.Cryptography
{
    internal static class Util
    {
        private static readonly List<byte[]> s_ids = new List<byte[]>();
        private static object s_syncLock = new object();
        private static RandomNumberGenerator s_rng = RandomNumberGenerator.Create();

        public static byte[] GenerateId()
        {
            lock(s_syncLock)
            {
                var iv = new byte[8];
                s_rng.GetBytes(iv);

                while(s_ids.Any(o => o.SequenceEqual(iv)))
                {
                    s_rng.GetBytes(iv);
                }

                s_ids.Add(iv);

                return iv;
            }
            
        }

        public static uint ToUInt32(this byte[] bytes)
        {
            return BitConverter.ToUInt32(bytes, 0);
        }

        public static uint ToUInt32(this byte[] bytes, int startIndex)
        {
            return BitConverter.ToUInt32(bytes, startIndex);
        }
    }
}
