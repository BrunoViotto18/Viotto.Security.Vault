using System.Diagnostics;
using System.Text;
namespace Viotto.Security;

public sealed class Base64Encoder
{
    private static readonly string Base64Characters = string.Join(string.Empty, Enumerable.Range(0, 26).Select(x => 'A' + x)
        .Concat(Enumerable.Range(0, 26).Select(x => 'a' + x))
        .Concat(Enumerable.Range(0, 10).Select(x => '0' + x))
        .Append('+')
        .Append('/')
        .Select(x => (char)x)
    );

    public string ToBase64(ReadOnlySpan<byte> rawBytes)
    {
        var padding = rawBytes.Length % 3 != 0 ? 3 - rawBytes.Length % 3 : 0;
        var capacity = (rawBytes.Length + padding) * 4 / 3;
        var sb = new StringBuilder(capacity);

        for (int i = 0; i < rawBytes.Length; i += 3)
        {
            var chunk = rawBytes.Slice(i, Math.Min(3, rawBytes.Length - i));

            int blob = 0;
            for (var j = 0; j < 3; j++)
            {
                if (j < chunk.Length)
                {
                    blob |= chunk[j];
                }

                blob <<= 8;
            }

            var max = chunk.Length + 1;
            for (int j = 0; j < max; j++)
            {
                var index = (blob >> 26) & 0b111111;
                sb.Append(Base64Characters[index]);
                blob <<= 6;
            }

            if (chunk.Length < 3)
            {
                sb.Append('=');
            }

            if (chunk.Length < 2)
            {
                sb.Append('=');
            }
        }

        return sb.ToString();
    }

    public byte[] FromBase64(string base64)
    {
        var capacity = base64.Length / 4 * 3;
        capacity -= base64.AsSpan()[^2..].Count('=');

        var rawBytes = new byte[capacity];

        for (int i = 0; i < base64.Length; i += 4)
        {
            var chunk = base64.AsSpan(i, 4);

            var blob = 0;
            for (int j = 0; j < 4; j++)
            {
                blob <<= 6;

                var character = chunk[j];
                if (character != '=')
                {
                    blob |= Base64Characters.IndexOf(character);
                }
            }

            var equalsIndex = chunk.IndexOf('=');
            if (equalsIndex == -1)
            {
                equalsIndex = 4;
            }

            for (int j = 0; j < equalsIndex - 1; j++)
            {
                var c = (byte)((blob >> 16) & 0b11111111);
                rawBytes[i / 4 * 3 + j] = c;
                blob <<= 8;
            }
        }

        return rawBytes;
    }
}
