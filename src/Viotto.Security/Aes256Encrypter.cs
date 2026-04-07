using System.Text;

namespace Viotto.Security;

public sealed class Aes256Encrypter
{
    private static readonly byte[] IV = Encoding.UTF8.GetBytes("0123456789abcdef");

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

    private static readonly byte[] RCon = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    ];

    public byte[] Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        var input = new byte[data.Length];
        data.CopyTo(input);

        Span<byte> expandedKeys = stackalloc byte[15 * 16];
        ExpandKeys(expandedKeys, key);

        var previousBlock = IV.AsSpan();

        for (int i = 0; i < input.Length; i += 16)
        {
            var block = input.AsSpan()[i..(i + 16)];
            Xor(block, previousBlock);

            EncryptBlock(block, expandedKeys);

            previousBlock = block;
        }

        return input;
    }

    private static void EncryptBlock(Span<byte> state, ReadOnlySpan<byte> expandedKey)
    {
        var firstKey = expandedKey[..16];
        Xor(state, firstKey);

        for (int round = 1; round < 15; round++)
        {
            SubBytes(state);
            ShiftRows(state);

            if (round != 14)
            {
                MixColumns(state);
            }

            var roundKey = expandedKey.Slice(round * 16, 16);
            Xor(state, roundKey);
        }
    }

    private static void ExpandKeys(Span<byte> expandedKeysBuffer, ReadOnlySpan<byte> key)
    {
        key.CopyTo(expandedKeysBuffer);

        for (int wordIndex = 8; wordIndex < 60; wordIndex++)
        {
            var previousWord = expandedKeysBuffer.Slice((wordIndex - 1) * 4, 4);
            var currentWord = expandedKeysBuffer.Slice(wordIndex * 4, 4);
            previousWord.CopyTo(currentWord);

            if (wordIndex % 8 == 0)
            {
                RotateLeft(currentWord);
                SubBytes(currentWord);
                currentWord[0] ^= RCon[wordIndex / 8];
            }
            else if (wordIndex % 8 == 4)
            {
                SubBytes(currentWord);
            }

            var someWord = expandedKeysBuffer.Slice((wordIndex - 8) * 4, 4);
            Xor(currentWord, someWord);
        }
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

    private static void SubBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            var value = data[i];
            data[i] = SBox[value];
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

    private static void MixColumns(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i += 4)
        {
            byte a = data[i + 0];
            byte b = data[i + 1];
            byte c = data[i + 2];
            byte d = data[i + 3];

            data[i + 0] = (byte)(Mix2(a) ^ Mix3(b) ^ c ^ d);
            data[i + 1] = (byte)(a ^ Mix2(b) ^ Mix3(c) ^ d);
            data[i + 2] = (byte)(a ^ b ^ Mix2(c) ^ Mix3(d));
            data[i + 3] = (byte)(Mix3(a) ^ b ^ c ^ Mix2(d));
        }
    }

    private static byte Mix2(byte value)
    {
        var hiBitSet = (value & 0x80) != 0;
        value <<= 1;
        if (hiBitSet)
        {
            value ^= 0x1b;
        }
        return value;
    }

    private static byte Mix3(byte value)
    {
        return (byte)(Mix2(value) ^ value);
    }
}
