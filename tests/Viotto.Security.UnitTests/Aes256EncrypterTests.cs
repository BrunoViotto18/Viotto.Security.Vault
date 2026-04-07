using System;
using System.Text;
using AwesomeAssertions;

namespace Viotto.Security.UnitTests;

public class AES256EncrypterTests
{
    private readonly Base64Encoder _base64Encoder;
    private readonly Aes256Encrypter _sut;

    public AES256EncrypterTests()
    {
        _base64Encoder = new Base64Encoder();
        _sut = new Aes256Encrypter();
    }

    [Theory]
    [InlineData("0123456789ABCDEF", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "rj4j0oXoIouySaSTartAsQ==")]
    [InlineData("0123456789ABCDEF", "abcdefghijklmnopqrstuvwxyz012345", "qcbRXhI2Vpjjvc5KdwQ13Q==")]
    public void Encrypt_ShouldEncryptData(string inputText, string key, string expected)
    {
        // Arrange
        var inputBytes = Encoding.UTF8.GetBytes(inputText);
        var keyBytes = Encoding.UTF8.GetBytes(key);

        // Act
        var output = _sut.Encrypt(inputBytes, keyBytes);

        // Assert
        var base64 = _base64Encoder.ToBase64(output);
        base64.Should().Be(expected);
    }
}
