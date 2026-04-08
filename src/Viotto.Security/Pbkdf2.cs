using System.Security.Cryptography;

namespace Viotto.Security;

public sealed class Pbkdf2
{
    public byte[] DeriveKey(byte[] password, byte[] salt, uint iterations, int length)
    {
        const int byteCount = 32;
        var blockCount = (int)Math.Ceiling(length / (double)byteCount);
        var buffer = new byte[length];
        Span<byte> bigEndianBuffer = stackalloc byte[4];
        for (int i = 0; i < blockCount * byteCount; i += byteCount)
        {
            ToBigEndian(bigEndianBuffer, (i / byteCount) + 1);

            using var hmac = new HMACSHA256(password);

            var firstHash = hmac.ComputeHash([.. salt, .. bigEndianBuffer]);

            var accumulator = firstHash;
            var previousHash = firstHash;
            for (int j = 0; j < iterations - 1; j++)
            {
                var newHash = hmac.ComputeHash(previousHash);

                for (int k = 0; k < accumulator.Length; k++)
                {
                    accumulator[k] ^= newHash[k];
                }

                previousHash = newHash;
            }

            accumulator[..Math.Min(byteCount, length - i)].CopyTo(buffer, i);
        }

        return buffer;
    }

    private static void ToBigEndian(Span<byte> buffer, int number)
    {
        buffer[0] = (byte)(number >> 24);
        buffer[1] = (byte)(number >> 16);
        buffer[2] = (byte)(number >> 8);
        buffer[3] = (byte)number;
    }
}
