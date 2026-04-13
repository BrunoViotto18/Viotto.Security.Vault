using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace Viotto.Security;

public sealed class Aes256Encrypter
{
    private const byte BlockSize = 16;

    private static readonly byte[] SBox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];

    private static readonly byte[] InvSBox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ];

    private static readonly byte[] RCon = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    ];

    public byte[] Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        var result = new byte[data.Length];
        data.CopyTo(result);

        Span<byte> expandedKeys = stackalloc byte[15 * BlockSize];
        ExpandKeys(expandedKeys, key);

        var previousBlock = iv;

        for (int i = 0; i < result.Length; i += BlockSize)
        {
            var block = result.AsSpan()[i..(i + BlockSize)];

            Xor(block, previousBlock);

            EncryptBlock(block, expandedKeys);

            previousBlock = block;
        }

        return result;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        var result = new byte[data.Length];
        data.CopyTo(result);

        Span<byte> expandedKeys = stackalloc byte[15 * BlockSize];
        ExpandKeys(expandedKeys, key);

        Span<byte> previousBlock = stackalloc byte[BlockSize];
        iv.CopyTo(previousBlock);

        Span<byte> originalBlock = stackalloc byte[BlockSize];
        for (int i = 0; i < result.Length; i += BlockSize)
        {
            var block = result.AsSpan()[i..(i + BlockSize)];

            block.CopyTo(originalBlock);

            DecryptBlock(block, expandedKeys);

            Xor(block, previousBlock);

            originalBlock.CopyTo(previousBlock);
        }

        return result;
    }

    private static void EncryptBlock(Span<byte> block, ReadOnlySpan<byte> expandedKey)
    {
        var firstKey = expandedKey[..BlockSize];
        Xor(block, firstKey);

        for (int round = 1; round < 15; round++)
        {
            SubBytes(block);
            ShiftRows(block);

            if (round != 14)
            {
                MixColumns(block);
            }

            var roundKey = expandedKey.Slice(round * BlockSize, BlockSize);
            Xor(block, roundKey);
        }
    }

    private static void DecryptBlock(Span<byte> block, ReadOnlySpan<byte> expandedKey)
    {
        for (int round = 14; round > 0; round--)
        {
            var roundKey = expandedKey.Slice(round * BlockSize, BlockSize);
            Xor(block, roundKey);

            if (round != 14)
            {
                UnmixColumns(block);
            }

            UnshiftRows(block);
            UnsubBytes(block);
        }

        var firstKey = expandedKey[..BlockSize];
        Xor(block, firstKey);
    }

    internal static void ExpandKeys(Span<byte> expandedKeysBuffer, ReadOnlySpan<byte> key)
    {
        key.CopyTo(expandedKeysBuffer);
        var expandedKeys = MemoryMarshal.Cast<byte, int>(expandedKeysBuffer);

        for (int wordIndex = 8; wordIndex < 60; wordIndex++)
        {
            var word = ReadWord(expandedKeys, wordIndex - 1);

            if (wordIndex % 8 == 0)
            {
                word = (int)BitOperations.RotateLeft((uint)word, 8);
                word = SubBytes(word);
                word = (word & 0x00FFFFFF) | (((word >> 24) ^ RCon[wordIndex / 8]) << 24);
            }
            else if (wordIndex % 8 == 4)
            {
                word = SubBytes(word);
            }

            word ^= ReadWord(expandedKeys, wordIndex - 8);

            WriteWord(expandedKeys, wordIndex, word);
        }
    }

    private static int ReadWord(ReadOnlySpan<int> expandedKeys, int index)
    {
        var word = expandedKeys[index];
        if (BitConverter.IsLittleEndian)
        {
            word = BinaryPrimitives.ReverseEndianness(word);
        }
        return word;
    }

    private static void WriteWord(Span<int> expandedKeys, int index, int word)
    {
        if (BitConverter.IsLittleEndian)
        {
            word = BinaryPrimitives.ReverseEndianness(word);
        }
        expandedKeys[index] = word;
    }

    private static void Xor(Span<byte> data, ReadOnlySpan<byte> value)
    {
        for (int i = 0; i < data.Length; i++)
        {
            data[i] ^= value[i];
        }
    }

    private static void RotateLeft(Span<byte> data, int n = 1)
    {
        n %= data.Length;

        if (n == 0)
        {
            return;
        }

        Span<byte> temp = stackalloc byte[n];
        data[..n].CopyTo(temp);
        data[n..].CopyTo(data);
        temp.CopyTo(data[^n..]);
    }

    private static void RotateRight(Span<byte> data, int n = 1)
    {
        n %= data.Length;

        if (n == 0)
        {
            return;
        }

        Span<byte> temp = stackalloc byte[n];
        data[^n..].CopyTo(temp);
        data[..^n].CopyTo(data[n..]);
        temp.CopyTo(data);
    }

    private static void SubBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            var value = data[i];
            data[i] = SBox[value];
        }
    }

    private static unsafe T SubBytes<T>(T data)
        where T : unmanaged, IBinaryInteger<T>
    {
        T result = T.Zero;
        var bits = sizeof(T) * 8;

        for (int shift = bits - 8; shift >= 0; shift -= 8)
        {
            result <<= 8;
            var index = byte.CreateTruncating(data >> shift);
            result |= T.CreateTruncating(SBox[index]);
        }

        return result;
    }

    private static void UnsubBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            var value = data[i];
            data[i] = InvSBox[value];
        }
    }

    private static void ShiftRows(Span<byte> data)
    {
        Span<byte> temp = stackalloc byte[4];

        for (int i = 0; i < 4; i++)
        {
            temp[0] = data[i + 0];
            temp[1] = data[i + 4];
            temp[2] = data[i + 8];
            temp[3] = data[i + 12];

            RotateLeft(temp, i);

            data[0 + i] = temp[0];
            data[4 + i] = temp[1];
            data[8 + i] = temp[2];
            data[12 + i] = temp[3];
        }
    }

    private static void UnshiftRows(Span<byte> data)
    {
        Span<byte> temp = stackalloc byte[4];

        for (int i = 0; i < 4; i++)
        {
            temp[0] = data[i + 0];
            temp[1] = data[i + 4];
            temp[2] = data[i + 8];
            temp[3] = data[i + 12];

            RotateRight(temp, i);

            data[0 + i] = temp[0];
            data[4 + i] = temp[1];
            data[8 + i] = temp[2];
            data[12 + i] = temp[3];
        }
    }

    private static void MixColumns(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i += 4)
        {
            byte a = data[i + 0];
            byte b = data[i + 1];
            byte c = data[i + 2];
            byte d = data[i + 3];

            data[i + 0] = (byte)(GFMul(a, 2) ^ GFMul(b, 3) ^ c ^ d);
            data[i + 1] = (byte)(a ^ GFMul(b, 2) ^ GFMul(c, 3) ^ d);
            data[i + 2] = (byte)(a ^ b ^ GFMul(c, 2) ^ GFMul(d, 3));
            data[i + 3] = (byte)(GFMul(a, 3) ^ b ^ c ^ GFMul(d, 2));
        }
    }

    private static void UnmixColumns(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i += 4)
        {
            byte a = data[i + 0];
            byte b = data[i + 1];
            byte c = data[i + 2];
            byte d = data[i + 3];

            data[i + 0] = (byte)(GFMul(a, 14) ^ GFMul(b, 11) ^ GFMul(c, 13) ^ GFMul(d, 9));
            data[i + 1] = (byte)(GFMul(a, 9) ^ GFMul(b, 14) ^ GFMul(c, 11) ^ GFMul(d, 13));
            data[i + 2] = (byte)(GFMul(a, 13) ^ GFMul(b, 9) ^ GFMul(c, 14) ^ GFMul(d, 11));
            data[i + 3] = (byte)(GFMul(a, 11) ^ GFMul(b, 13) ^ GFMul(c, 9) ^ GFMul(d, 14));
        }
    }

    private static byte XTime(byte x)
    {
        var hiBitSet = (x & 0x80) != 0;
        x <<= 1;
        if (hiBitSet)
        {
            x ^= 0x1b;
        }
        return x;
    }

    private static byte GFMul(byte x, byte y)
    {
        byte result = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((y & 1) != 0)
            {
                result ^= x;
            }

            x = XTime(x);
            y >>= 1;
        }

        return result;
    }
}
