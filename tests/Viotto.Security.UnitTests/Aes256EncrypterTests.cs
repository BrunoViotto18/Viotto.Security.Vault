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
    [InlineData("0123456789ABCDEF", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0123456789abcdef", "rj4j0oXoIouySaSTartAsQ==")]
    [InlineData("0123456789ABCDEF", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "qcbRXhI2Vpjjvc5KdwQ13Q==")]
    public void Encrypt_ShouldEncryptData(string inputText, string key, string iv, string expected)
    {
        // Arrange
        var inputBytes = Encoding.UTF8.GetBytes(inputText);
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var ivBytes = Encoding.UTF8.GetBytes(iv);

        // Act
        var output = _sut.Encrypt(inputBytes, keyBytes, ivBytes);

        // Assert
        var base64 = _base64Encoder.ToBase64(output);
        base64.Should().Be(expected);
    }

    [Theory]
    [InlineData("rj4j0oXoIouySaSTartAsQ==", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0123456789abcdef", "0123456789ABCDEF")]
    [InlineData("qcbRXhI2Vpjjvc5KdwQ13Q==", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "0123456789ABCDEF")]
    public void Decrypt_ShouldDecryptData(string encryptedData, string key, string iv, string expected)
    {
        // Arrange
        var inputBytes = _base64Encoder.FromBase64(encryptedData);
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var ivBytes = Encoding.UTF8.GetBytes(iv);

        // Act
        var output = _sut.Decrypt(inputBytes, keyBytes, ivBytes);

        // Assert
        var base64 = Encoding.UTF8.GetString(output);
        base64.Should().Be(expected);
    }
}
