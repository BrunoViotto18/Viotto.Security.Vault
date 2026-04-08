using System.Text;
using AwesomeAssertions;

namespace Viotto.Security.UnitTests;

public class Pbkdf2Tests
{
    private readonly Base64Encoder _base64Encoder;
    private readonly Pbkdf2 _sut;

    public Pbkdf2Tests()
    {
        _base64Encoder = new Base64Encoder();
        _sut = new Pbkdf2();
    }

    [Theory]
    [InlineData("test", "salt", 100_000, 32, "WROQMEoSF6ZeUgb5Q3QOqqi1KOlqXIvDpAiE02ki6+A=")]
    [InlineData("iteration1", "salt1", 10_000, 32, "1N+pCHuF51vWEuGibzC0WNaGbtybhcy03V+YuxrykAo=")]
    [InlineData("iteration2", "salt1", 100_000, 32, "zFtg6Ge13PSIfBvZTmLj23OqXBo7D77uCCHh6TTgjq0=")]
    [InlineData("iteration3", "salt1", 1_000_000, 32, "ulsw1YT0Pmii5qN9ILtT7Tw0NwQEQij8N4KYACHEOsk=")]
    [InlineData("length1", "salt2", 100_000, 16, "0ZY/FcnhIfoCcnlcShldiA==")]
    [InlineData("length2", "salt2", 100_000, 24, "B8YqY6NjRIcjTqK2nDnLEZ3rLWi2tufI")]
    [InlineData("length3", "salt2", 100_000, 32, "oLGM1TdREB3slx6JYk0z9YpWAT/Ontg7QhjriOlq9to=")]
    [InlineData("length4", "salt2", 100_000, 48, "c1Q7J8+s5s+8IPbnFxW3zXwfGc7ZFx4RhjpHIjZXSWhbtYEIVZk5mPz8aig9yuLG")]
    [InlineData("length5", "salt2", 100_000, 64, "OI+ts3djyxtsHgeCD3Yq185wP6JBa3hBI7N79Ah8RhMMXeiVkAwZcMlyj7u1hrM0iMmdy1ZWDzczqwmuCTpBQQ==")]
    public void DiriveKey_ShouldDeriveKey(string password, string salt, uint iterations, int length, string expected)
    {
        // Arrange
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        // Act
        var output = _sut.DeriveKey(passwordBytes, saltBytes, iterations, length);

        // Assert
        var base64Output = _base64Encoder.ToBase64(output);
        base64Output.Should().Be(expected);
    }
}
