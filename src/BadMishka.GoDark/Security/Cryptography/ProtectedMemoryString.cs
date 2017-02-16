using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace BadMishka.Security.Cryptography
{
    /// <summary>
    /// Stores a string encrypted in memory, if the string is loaded as bytes.
    /// Once the string is unprotected, it can be found in the memory of the 
    /// application. 
    /// </summary>
    public class ProtectedMemoryString : ProtectedMemoryBinary, IEquatable<ProtectedMemoryString>
    {
        private string text;
        private readonly int length;
        private int hashCode;
        private static readonly System.Text.Encoding utf8 = System.Text.Encoding.UTF8;
        private bool disposed = false;

        public ProtectedMemoryString(byte[] binary, bool encrypt = true) :base(binary, encrypt)
        {
            if (binary == null)
                throw new ArgumentNullException("value");

            this.length = utf8.GetCharCount(binary);
            using (var sha512 = SHA512.Create())
            {
                var hashBytes = sha512.ComputeHash(binary);
                this.hashCode = MurMurHash3.ComputeHash(hashBytes, 20);
            }
        }

       



        public ProtectedMemoryString(string value): base()
        {
            if (value == null)
                throw new ArgumentNullException("value");

            this.text = value;
            this.length = value.Length;
            this.hashCode = MurMurHash3.ComputeHash(utf8.GetBytes(value), 20);
        }

        public override int Length
        {
            get
            {
                return this.length;
            }
        }

        public string Unprotect()
        {
            if (this.disposed)
                throw new ObjectDisposedException($"ProtectedMemoryString {this.Id}");

            if (this.text != null)
                return this.text;

            var binary = this.UnprotectAndCopyData();
            if (binary.Length == 0)
                return string.Empty;

           
            var result = utf8.GetString(binary, 0, this.Length);
            this.hashCode = MurMurHash3.ComputeHash(binary, 20);
            Array.Clear(binary, 0, binary.Length);

            this.text = result;
            return result;
        }

        public override byte[] UnprotectAndCopyData()
        {
            if (this.disposed)
                throw new ObjectDisposedException($"ProtectedMemoryString {this.Id}");

            if (this.text != null)
                return utf8.GetBytes(this.text);

            return base.UnprotectAndCopyData();
        }

        public override int GetHashCode()
        {
            return this.hashCode;
        }

        public bool Equals(ProtectedMemoryString other)
        {
            if (this.disposed)
                throw new ObjectDisposedException($"ProtectedMemoryString {this.Id}");

            if (other == null)
                return false;

            if (this.Length != other.Length)
                return false;

            if (this.Id.EqualTo(other.Id))
                return true;

            if (this.text != other.text)
                return false;

            return base.Equals((ProtectedMemoryBinary)other);
        }

        protected override void Dispose(bool disposing)
        {
            if (this.disposed)
                return;

            this.disposed = true;
            if(disposing)
            {
                this.hashCode = 0;
                this.text = null;
            }
            base.Dispose(disposing);
        }
    }
}
