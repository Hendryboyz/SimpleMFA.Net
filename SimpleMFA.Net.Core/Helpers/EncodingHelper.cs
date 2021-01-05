using System.Linq;
using System.Collections.Generic;

namespace SimpleMFA.Net.Core.Helpers
{
    public static class EncodingHelper
    {
        private const string BASE32_CHARACTERS = @"ABCDEFGH" //  7
                                                + "IJKLMNOP" // 15
                                                + "QRSTUVWX" // 23
                                                + "YZ234567" // 31
                                                + "=";  // padding char;

        public static int[] VALID_PADDING_COUNT = new int[] { 6, 4, 3, 1, 0 };

        public static byte[] Base32DecodeString(string base32String)
        {
            if (string.IsNullOrEmpty(base32String) || IsValidatePadding(base32String) == false)
            {
                return new byte[0];
            }
			
            base32String = base32String.TrimEnd(BASE32_CHARACTERS[32]);

            int base32BitCount = 5;
            var result = new List<byte>();
            for (var bitIndex = 0; bitIndex < base32String.Length * base32BitCount; bitIndex += 8)
            {
                int byteOffset = bitIndex / base32BitCount;
                var dualByte = BASE32_CHARACTERS.IndexOf(base32String[byteOffset]) << 10;
                if (byteOffset + 1 < base32String.Length)
                {
                    dualByte |= BASE32_CHARACTERS.IndexOf(base32String[byteOffset + 1]) << 5;
                }
                if (byteOffset + 2 < base32String.Length)
                {
                    dualByte |= BASE32_CHARACTERS.IndexOf(base32String[byteOffset + 2]);
                }
                int previousBitCount = bitIndex % base32BitCount;
                var singleByte = 0xff & (dualByte >> (15 - previousBitCount - 8));
                result.Add((byte)(singleByte));
            }

            return result.ToArray();
        }

        private static bool IsValidatePadding(string rawSecretKey)
        {
            char padding = BASE32_CHARACTERS[32];
            int paddingCount = rawSecretKey.Count(c => c == padding);
            bool isValidPaddintCount = VALID_PADDING_COUNT.Contains(paddingCount);

            bool isValidPaddingPosition = true;
            for (int i = 0; i < VALID_PADDING_COUNT.Length - 1; i++)
            {
                int count = VALID_PADDING_COUNT[i];
                if (count == paddingCount)
                {
                    int lastIndex = rawSecretKey.Length - 1;
                    isValidPaddingPosition = rawSecretKey.Substring(lastIndex - count).Equals(new string(padding, count));
                    break;
                }
            }

            return isValidPaddintCount & isValidPaddingPosition;
        }
    }
}