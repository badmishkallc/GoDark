using System;
using System.Security.Cryptography;
using static BadMishka.Bits.BitHelpers;

namespace BadMishka.Security.Cryptography
{
    /// <summary>
    /// An implementation of Salsa20, a stream cipher proposed by Daniel J. Bernstein available for
    /// use in the public domain. 
    /// </summary>
    public class Salsa20 : SymmetricAlgorithm
    {
        private static readonly KeySizes[] s_legalBlockSizes;
        private static readonly KeySizes[] s_legalKeySizes;
        private RandomNumberGenerator rng;

        static Salsa20()
        {
           s_legalBlockSizes  = new[] { new KeySizes(64, 64, 0) };
           s_legalKeySizes = new[] { new KeySizes(128, 256, 128) };
        }
       

        protected Salsa20()
        {
#if !DOTNET5_4
            LegalBlockSizesValue = s_legalBlockSizes;
            LegalKeySizesValue = s_legalKeySizes;
#endif
            this.BlockSize = 64;
            this.KeySize = 256;
            this.Rounds = Salsa20Rounds.Ten;
            this.rng = RandomNumberGenerator.Create();
        }

        public Salsa20Rounds Rounds { get; set; }


        public override KeySizes[] LegalBlockSizes
        {
            get
            {
                return s_legalBlockSizes;
            }
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                return s_legalKeySizes;
            }
        }

#pragma warning disable CS0109
        public static new Salsa20 Create()
        {
            return new Salsa20();
        }
#pragma warning restore  CS0109

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new Salsa20CryptoTransform(rgbKey, rgbIV, (int)this.Rounds);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new Salsa20CryptoTransform(rgbKey, rgbIV, (int)this.Rounds);
        }

        public override void GenerateIV()
        {
            this.IV = GetRandomBytes(rng, this.BlockSize / 8);
        }

        public override void GenerateKey()
        {
            this.Key = GetRandomBytes(this.rng, this.KeySize / 8);
        }

        private static byte[] GetRandomBytes(RandomNumberGenerator rng, int byteCount)
        {
            byte[] bytes = new byte[byteCount];
            rng.GetBytes(bytes);
            return bytes;
        }

        private class Salsa20CryptoTransform : ICryptoTransform
        {
            // https://dotnetfiddle.net/Bh4ijW
            private static readonly uint[] Sigma = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 };
            private static readonly uint[] Tau = new uint[] { 0x61707865, 0x3120646E, 0x79622D36, 0x6B206574 };
            private uint[] state;
            private uint[] reusableBuffer = new uint[16];
            private int rounds = 10;
            private bool isDisposed = false;

            public Salsa20CryptoTransform(byte[] key, byte[] iv, int rounds)
            {
                this.state = CreateState(key, iv);
                this.rounds = rounds;
            }

            public bool CanReuseTransform
            {
                get
                {
                    return false;
                }
            }

            public bool CanTransformMultipleBlocks
            {
                get
                {
                    return true;
                }
            }

            public int InputBlockSize
            {
                get
                {
                    return 64;
                }
            }

            public int OutputBlockSize
            {
                get
                {
                    return 64;
                }
            }

            

            private static void AddRotateXor(uint[] state, uint[] buffer, byte[] output, int rounds)
            {
                Array.Copy(state, buffer, 16);
                var v = buffer;

                for (var i = 0; i < rounds; i++)
                {
                    v[4] ^= RotateLeft32(v[0] + v[12], 7);
                    v[8] ^= RotateLeft32(v[4] + v[0], 9);
                    v[12] ^= RotateLeft32(v[8] + v[4], 13);
                    v[0] ^= RotateLeft32(v[12] + v[8], 18);
                    v[9] ^= RotateLeft32(v[5] + v[1], 7);
                    v[13] ^= RotateLeft32(v[9] + v[5], 9);
                    v[1] ^= RotateLeft32(v[13] + v[9], 13);
                    v[5] ^= RotateLeft32(v[1] + v[13], 18);
                    v[14] ^= RotateLeft32(v[10] + v[6], 7);
                    v[2] ^= RotateLeft32(v[14] + v[10], 9);
                    v[6] ^= RotateLeft32(v[2] + v[14], 13);
                    v[10] ^= RotateLeft32(v[6] + v[2], 18);
                    v[3] ^= RotateLeft32(v[15] + v[11], 7);
                    v[7] ^= RotateLeft32(v[3] + v[15], 9);
                    v[11] ^= RotateLeft32(v[7] + v[3], 13);
                    v[15] ^= RotateLeft32(v[11] + v[7], 18);
                    v[1] ^= RotateLeft32(v[0] + v[3], 7);
                    v[2] ^= RotateLeft32(v[1] + v[0], 9);
                    v[3] ^= RotateLeft32(v[2] + v[1], 13);
                    v[0] ^= RotateLeft32(v[3] + v[2], 18);
                    v[6] ^= RotateLeft32(v[5] + v[4], 7);
                    v[7] ^= RotateLeft32(v[6] + v[5], 9);
                    v[4] ^= RotateLeft32(v[7] + v[6], 13);
                    v[5] ^= RotateLeft32(v[4] + v[7], 18);
                    v[11] ^= RotateLeft32(v[10] + v[9], 7);
                    v[8] ^= RotateLeft32(v[11] + v[10], 9);
                    v[9] ^= RotateLeft32(v[8] + v[11], 13);
                    v[10] ^= RotateLeft32(v[9] + v[8], 18);
                    v[12] ^= RotateLeft32(v[15] + v[14], 7);
                    v[13] ^= RotateLeft32(v[12] + v[15], 9);
                    v[14] ^= RotateLeft32(v[13] + v[12], 13);
                    v[15] ^= RotateLeft32(v[14] + v[13], 18);
                }

                for (int i = 0; i < 16; ++i)
                {
                    v[i] += state[i];
                    output[i << 2] = (byte)v[i];
                    output[(i << 2) + 1] = (byte)(v[i] >> 8);
                    output[(i << 2) + 2] = (byte)(v[i] >> 16);
                    output[(i << 2) + 3] = (byte)(v[i] >> 24);
                }

                state[8]++;
                if (state[8] == 0)
                    state[9]++;
            }

            private static uint[] CreateState(byte[] key, byte[] iv)
            {
                int offset = key.Length - 16;
                uint[] expand = key.Length == 32 ? Sigma : Tau;
                uint[] state = new uint[16];

                // key
                state[1] = key.ToUInt32(0);
                state[2] = key.ToUInt32(4);
                state[3] = key.ToUInt32(8);
                state[4] = key.ToUInt32(12);

                // key offset
                state[11] = key.ToUInt32(offset + 0);
                state[12] = key.ToUInt32(offset + 4);
                state[13] = key.ToUInt32(offset + 8);
                state[14] = key.ToUInt32(offset + 12);

                // sigma / tau 
                state[0] = expand[0];
                state[5] = expand[1];
                state[10] = expand[2];
                state[15] = expand[3];

                state[6] = iv.ToUInt32(0);
                state[7] = iv.ToUInt32(4);
                state[8] = 0;
                state[9] = 0;

                return state;
            }

            public void Dispose()
            {
                this.Dispose(true);
                GC.SuppressFinalize(this);
            }

            protected void Dispose(bool isDisposing)
            {
                if(isDisposing)
                {
                    Array.Clear(this.reusableBuffer, 0, this.reusableBuffer.Length);
                    Array.Clear(this.state, 0, this.state.Length);
                    this.reusableBuffer = null;
                    this.state = null;
                    this.isDisposed = true;
                }
            }

            ~Salsa20CryptoTransform()
            {
                this.Dispose(false);
            }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                this.CheckDisposed();

                byte[] output = new byte[this.OutputBlockSize];
                int bytesTransformed = 0;
                int blockSize = 0;
                while(inputCount > 0)
                {
                    AddRotateXor(this.state, this.reusableBuffer, output, this.rounds);

                    blockSize = Math.Min(64, inputCount);

                    for (int i = 0; i <  blockSize; i++)
                        outputBuffer[outputOffset + i] = (byte)(inputBuffer[inputOffset + i] ^ output[i]);

                    bytesTransformed += blockSize;
                    inputCount -= 64;
					outputOffset += 64;
					inputOffset += 64;
                }

                return bytesTransformed;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                this.CheckDisposed();

                byte[] output = new byte[inputCount];
                TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
                return output;
            }

            private void CheckDisposed()
            {
                if (this.isDisposed)
                    throw new ObjectDisposedException("ICryptoTransform is already disposed");
            }
        }
    }
}
