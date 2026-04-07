using System.Text;
using AwesomeAssertions;

namespace Viotto.Security.UnitTests;

public class Base64EncoderTests
{
    private readonly Base64Encoder _sut;

    public Base64EncoderTests()
    {
        _sut = new Base64Encoder();
    }

    [Theory]
    [InlineData("ABA", "QUJB")]
    [InlineData("ABAA", "QUJBQQ==")]
    [InlineData("ABAAB", "QUJBQUI=")]
    [InlineData("ABAABA", "QUJBQUJB")]
    [InlineData("Teste123Teste123", "VGVzdGUxMjNUZXN0ZTEyMw==")]
    public void ToBase64_ShouldEncodeString(string input, string expected)
    {
        // Arrange
        var rawBytes = Encoding.UTF8.GetBytes(input);

        // Act
        var base64 = _sut.ToBase64(rawBytes);

        // Assert
        base64.Should().Be(expected);
    }

    [Theory]
    [InlineData("QUJB", "ABA")]
    [InlineData("QUJBQQ==", "ABAA")]
    [InlineData("QUJBQUI=", "ABAAB")]
    [InlineData("QUJBQUJB", "ABAABA")]
    [InlineData("VGVzdGUxMjNUZXN0ZTEyMw==", "Teste123Teste123")]
    public void FromBase64_ShouldDecodeString(string input, string textOutput)
    {
        // Arrange

        // Act
        var rawBytes = _sut.FromBase64(input);

        // Assert
        var text = Encoding.UTF8.GetString(rawBytes);
        text.Should().Be(textOutput);
    }
}
