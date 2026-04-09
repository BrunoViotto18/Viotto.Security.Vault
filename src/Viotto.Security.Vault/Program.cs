using System.Text;
using Viotto.Security;
using System.Security.Cryptography;

var _pbkdf2 = new Pbkdf2();
var _pkcs7 = new Pkcs7();
var _base64Encoder = new Base64Encoder();
var _aesEncrypter = new Aes256Encrypter();

if (args.Length == 0)
{
    await Console.Error.WriteLineAsync("O programa não recebeu nenhum comando");
    return;
}

if (args[0] is "cifrar" or "decifrar" && args.Length != 2)
{
    await Console.Error.WriteLineAsync($"O comando \"{args[0]}\" não recebeu o parâmetro de arquivo obrigatório, ou recebeu mais parâmetros do que o permitido");
    return;
}

if (args[0] is "testar" && args.Length != 1)
{
    await Console.Error.WriteLineAsync("O comando \"testar\" recebeu mais parâmentros do que o permitido");
    return;
}

switch (args[0])
{
    case "cifrar":
        await EncryptAsync(args[1]);
        break;

    case "decifrar":
        await DecryptAsync(args[1]);
        break;

    case "testar":
        await TestAsync();
        break;

    default:
        await Console.Error.WriteLineAsync($"O comando \"{args[0]}\" não é válido");
        break;
}

async Task EncryptAsync(string filePath)
{
    Console.Write("Digite a senha para criptografar o arquivo: ");
    var password = Console.ReadLine();

    if (password is null or { Length: 0 })
    {
        await Console.Error.WriteLineAsync("Senha inválida!");
        return;
    }

    var salt = RandomNumberGenerator.GetBytes(16);
    var derivedPassword = DerivePassword(password, salt);

    var fileContent = await File.ReadAllTextAsync(filePath);
    var fileBinary = Encoding.UTF8.GetBytes(fileContent);
    fileBinary = _pkcs7.AddPadding(fileBinary, 16);

    var iv = RandomNumberGenerator.GetBytes(16);
    var encryptedData = _aesEncrypter.Encrypt(fileBinary, derivedPassword, iv);
    var base64EncryptedData = _base64Encoder.ToBase64([.. salt, .. iv, .. encryptedData]);

    var fileName = Path.GetFileName(filePath);
    var outputFilePath = Path.Join(Directory.GetCurrentDirectory(), $"{fileName}.cifrado");
    await File.WriteAllTextAsync(outputFilePath, base64EncryptedData);
}

async Task DecryptAsync(string filePath)
{
    Console.Write("Digite a senha para descriptografar o arquivo: ");
    var password = Console.ReadLine();

    if (password is null or { Length: 0 })
    {
        await Console.Error.WriteLineAsync("Senha inválida!");
        return;
    }

    var base64FileContent = await File.ReadAllTextAsync(filePath);
    var binaryFileContent = _base64Encoder.FromBase64(base64FileContent);

    var salt = binaryFileContent[..16];
    var iv = binaryFileContent[16..32];
    var encryptedData = binaryFileContent[32..];

    var derivedPassword = DerivePassword(password, salt);

    byte[] binaryData;
    try
    {
        binaryData = _aesEncrypter.Decrypt(encryptedData, derivedPassword, iv);
        binaryData = _pkcs7.RemovePadding(binaryData, 16);
    }
    catch (InvalidOperationException)
    {
        await Console.Error.WriteLineAsync("Falha para decriptar o arquivo");
        return;
    }

    var data = Encoding.UTF8.GetString(binaryData);

    Console.WriteLine("Mensagem decifrada:");
    Console.WriteLine(data);
}

async Task TestAsync()
{
    byte[] key = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000000");
    byte[] iv = Convert.FromHexString("00000000000000000000000000000000");
    byte[] data = Convert.FromHexString("014730f80ac625fe84f026c60bfd547d");
    byte[] expected = Convert.FromHexString("5c9d844ed46f9885085e5d6a4f94c7d7");

    var output = _aesEncrypter.Encrypt(data, key, iv);

    if (output.Length != expected.Length)
    {
        Console.WriteLine("FALHA");
        return;
    }

    if (output.Zip(expected).Any(x => x.First != x.Second))
    {
        Console.WriteLine("FALHA");
        return;
    }

    Console.WriteLine("SUCESSO");
}

byte[] DerivePassword(string password, byte[] salt)
{
    var passwordBytes = Encoding.UTF8.GetBytes(password);

    var derivedKey = _pbkdf2.DeriveKey(passwordBytes, salt, 100_000, 32);

    return derivedKey;
}
