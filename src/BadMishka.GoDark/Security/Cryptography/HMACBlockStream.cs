using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BadMishka.Security.Cryptography
{
    /// <summary>
    /// Hash-Based Message Authenticated Code Stream designed for use with MAC-then-Ecrypt 
    /// and Encrypt-then-MAC scenarios.
    /// </summary>
    public class HMACBlockStream : System.IO.Stream
    {
        private Stream innerStream;
        private BinaryReader reader;
        private BinaryWriter writer;
        private bool endOfStream = false;
        private byte[] endOfStreamMarker = new byte[32];
        private Func<HashAlgorithm> hashFactory;
        private byte[] internalBuffer;
        private int expectedPosition = 0;
        private bool disposed;
        private int bufferOffset = 0;

        public HMACBlockStream(Stream innerStream, bool write = true)
            :this(innerStream, write, new System.Text.UTF8Encoding(false, false), null)
        {

        }

        public HMACBlockStream(Stream innerStream, bool write, Encoding encoding, Func<HashAlgorithm> hashFactory)
        {
            if (innerStream == null)
                throw new ArgumentNullException(nameof(innerStream));

            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));

            this.innerStream = innerStream;

            if (hashFactory == null)
            {
                hashFactory = () => SHA256.Create();
            }


            if (write)
                this.writer = new BinaryWriter(innerStream, encoding);
            else
                this.reader = new BinaryReader(innerStream, encoding);

            this.hashFactory = hashFactory;
        }

        public override bool CanRead
        {
            get
            {
                return this.reader != null;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return this.writer != null;
            }
        }

        public override long Length
        {
            get
            {
                return this.innerStream.Length;
            }
        }

        public override long Position
        {
            get
            {
                return this.innerStream.Position;
            }

            set
            {
                throw new NotSupportedException();
            }
        }

        public override void Flush()
        {
            if (this.writer != null)
                this.writer.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (this.reader == null)
                throw new InvalidOperationException("MACStream cannot read");

            if (this.internalBuffer == null)
            {
                this.bufferOffset = 0;
                this.internalBuffer = this.ReadNext();
                if (this.internalBuffer == null)
                    return 0;
            }

            int l = Math.Min(this.internalBuffer.Length - this.bufferOffset, count);


            Array.Copy(this.internalBuffer, this.bufferOffset, buffer, offset, l);
            offset += l;
            this.bufferOffset += l;

            if (this.bufferOffset == this.internalBuffer.Length)
                this.internalBuffer = null;


            return l;
        }

        private byte[] ReadNext()
        {
            if (this.endOfStream)
                return null;

            int actualPosition = reader.ReadInt32();
            if (this.expectedPosition != actualPosition)
                throw new Exception($"The stream's actual position {actualPosition} does not match the expected position {this.expectedPosition} ");

            this.expectedPosition++;
            byte[] expectedHash = reader.ReadBytes(32);
            int bufferSize = reader.ReadInt32();

            if (bufferSize == 0)
            {
                if (!endOfStreamMarker.EqualTo(expectedHash))
                    throw new Exception("invalid end-of-stream marker");

                this.endOfStream = true;
                return null;
            }

            byte[] decryptedBytes = reader.ReadBytes(bufferSize);

            using (var hash = this.hashFactory())
            {
                byte[] actualHash = hash.ComputeHash(decryptedBytes);
                if (!expectedHash.EqualTo(actualHash))
                    throw new Exception("The file is corrupted or has been tampered with.");

                expectedHash.Clear();
                actualHash.Clear();
            }

            return decryptedBytes;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (this.writer == null)
                throw new InvalidOperationException($"MACStream cannot write.");

            this.writer.Write(this.expectedPosition);
            this.expectedPosition++;

            var length = count - offset;
            var bytes = new byte[length];
            Array.Copy(buffer, bytes, length);

            using (var hash = this.hashFactory())
            {
                var hashBytes = hash.ComputeHash(bytes);
                this.writer.Write(hashBytes);
            }

            this.writer.Write(length);
            this.writer.Write(bytes);
        }

        protected override void Dispose(bool disposing)
        {
            if (this.disposed)
                return;

            this.disposed = true;
            if (disposing)
            {
                if (this.innerStream == null)
                    return;

                if (this.reader != null)
                    this.reader.Dispose();

                if (this.writer != null)
                {
                    this.WriteEndOfStream();
                    this.Flush();
                    this.writer.Dispose();
                }


                this.innerStream.Dispose();
            }

            base.Dispose(disposing);
        }

        protected virtual void WriteEndOfStream()
        {
            this.writer.Write(this.expectedPosition);
            this.writer.Write(new byte[32]);
            this.writer.Write(0);
        }
    }
}
