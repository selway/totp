using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TOTP.Core
{
    /// <summary>
    /// TOTP implementation
    /// of https://tools.ietf.org/html/rfc6238
    /// </summary>
    public class TOTP
    {
        /// <summary>
        /// get unix timestamp
        /// </summary>
        /// <param name="baseTime">basic time</param>
        /// <returns>unix timestamp</returns>
        private static Int64 GetUnixTimestamp(DateTime basicTime)
        {
            return Convert.ToInt64(Math.Round((DateTime.UtcNow - basicTime).TotalSeconds));
        }


        /// <summary>
        /// get timestamp
        /// basic time 1970-1-1 0：0：0
        /// </summary>
        /// <param name="timeStep">timestamp step，default 30 seconds</param>
        /// <returns></returns>
        private static Int64 GetTimestamp(int timeStep = 30)
        {
            Int64 Timestamp = GetUnixTimestamp(new DateTime(1970, 1, 1, 0, 0, 0));
            Timestamp = Convert.ToInt64(Timestamp / timeStep);
            return Timestamp;
        }

        /// <summary>
        /// get timestamp
        /// </summary>
        /// <param name="basicTime">basic time</param>
        /// <param name="timeStep">timestamp step，default 30 seconds</param>
        /// <returns></returns>
        private static Int64 GetTimestamp(DateTime basicTime, int timeStep = 30)
        {
            Int64 Timestamp = GetUnixTimestamp(basicTime);
            Timestamp = Convert.ToInt64(Timestamp / timeStep);
            return Timestamp;
        }

        /// <summary>
        /// get remaining effective seconds
        /// </summary>
        /// <param name="basicTime">basic time</param>
        /// <returns></returns>
        public static int GetEffectiveSeconds(int timeStep = 30)
        {
            Int64 unixTimestamp = GetUnixTimestamp(new DateTime(1970, 1, 1, 0, 0, 0));
            return timeStep - Convert.ToInt32(unixTimestamp % timeStep);
        }

        /// <summary>
        /// get remaining effective seconds
        /// </summary>
        /// <param name="basicTime">basic time</param>
        /// <param name="timeStep">timestamp step，default 30 seconds</param>
        /// <returns></returns>
        public static int GetEffectiveSeconds(DateTime basicTime, int timeStep = 30)
        {
            Int64 unixTimestamp = GetUnixTimestamp(basicTime);
            return timeStep - Convert.ToInt32(unixTimestamp % timeStep);
        }


        /// <summary>
        /// This method generates a TOTP value for the given set of parameters.
        /// </summary>
        /// <param name="key">the shared secret</param>
        /// <param name="timeStep">timestamp step</param>
        /// <param name="codeDigits">number of digits to totp</param>
        /// <param name="algorithm">algorithm of hash</param>
        /// <returns>totp</returns>
        public static int GenerateTOTP(byte[] key, int timeStep = 30, int codeDigits = 6, HmacAlgorithm algorithm = HmacAlgorithm.HMACSHA1)
        {
            int divisor = Convert.ToInt32(Math.Pow(10, codeDigits));

            var data = BitConverter.GetBytes(GetTimestamp(timeStep)).Reverse().ToArray();
            string algorithmName = Enum.GetName(typeof(HmacAlgorithm), algorithm);
            HMAC hmac = HMAC.Create(algorithmName);
            hmac.Key = key;
            byte[] hash = hmac.ComputeHash(data);
            int offset = hash.Last() & 0x0F;
            int oneTimePassword = (
                 ((hash[offset + 0] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff)
                     ) % divisor;
            return oneTimePassword;
        }

        /// <summary>
        /// This method generates a TOTP value for the given set of parameters.
        /// </summary>
        /// <param name="basicTime">basic time</param>
        /// <param name="key">the shared secret</param>
        /// <param name="timeStep">timestamp step</param>
        /// <param name="codeDigits">number of digits to totp</param>
        /// <param name="algorithm">algorithm of hash</param>
        /// <returns>totp</returns>
        public static int GenerateTOTP(DateTime basicTime, byte[] key, int timeStep = 30, int codeDigits = 6, HmacAlgorithm algorithm = HmacAlgorithm.HMACSHA1)
        {
            int divisor = Convert.ToInt32(Math.Pow(10, codeDigits));

            var data = BitConverter.GetBytes(GetTimestamp(basicTime, timeStep)).Reverse().ToArray();
            string algorithmName = Enum.GetName(typeof(HmacAlgorithm), algorithm);
            HMAC hmac = HMAC.Create(algorithmName);
            hmac.Key = key;
            byte[] hash = hmac.ComputeHash(data);
            int offset = hash.Last() & 0x0F;
            int oneTimePassword = (
                 ((hash[offset + 0] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff)
                     ) % divisor;
            return oneTimePassword;
        }
    }
}
