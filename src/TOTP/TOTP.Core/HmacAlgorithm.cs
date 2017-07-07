using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TOTP.Core
{
    /// <summary>
    /// HMAC algorithms
    /// </summary>
    public enum HmacAlgorithm
    {
        /// <summary>
        /// SHA1 hash algorithm
        /// </summary>
        HMACSHA1,
        /// <summary>
        /// SHA256 hash algorithm
        /// </summary>
        HMACSHA256,
        /// <summary>
        /// SHA384 hash algorithm
        /// </summary>
        HMACSHA384,
        /// <summary>
        /// SHA512 hash algorithm
        /// </summary>
        HMACSHA512,
        /// <summary>
        /// MD5 hash algorithm
        /// </summary>
        HMACMD5,
        /// <summary>
        /// RIPEMD160 hash algorithm
        /// </summary>
        HMACRIPEMD160
    }
}
