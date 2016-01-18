using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BadMishka.Security.Cryptography
{
    public enum DataProtectionActionType
    {
        Encrypt,
        Decrypt
    }

    public delegate byte[] DataProtectionAction(byte[] binary, object state, DataProtectionActionType action);
}
