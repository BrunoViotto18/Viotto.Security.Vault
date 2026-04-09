using System.Text;
using Viotto.Security;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.RegularExpressions;

var _pbkdf2 = new Pbkdf2();
var _pkcs7 = new Pkcs7();
var _base64Encoder = new Base64Encoder();
var _aesEncrypter = new Aes256Encrypter();
var _nistRegexFilter = new Regex("^CBC(?!MCT).*?256$", RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.ExplicitCapture);
var _nistEntryRegex = new Regex(@"^COUNT = (?<count>\d+)\nKEY = (?<key>[^\n]+)\nIV = (?<iv>[^\n]+)\n(?:PLAINTEXT|CIPHERTEXT) = (?<input>[^\n]+)\n(?:PLAINTEXT|CIPHERTEXT) = (?<output>[^\n]+)$", RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.ExplicitCapture);


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
    var nistDirectory = Path.Join(Directory.GetCurrentDirectory(), "nist");
    var files = Directory.EnumerateFiles(nistDirectory, "*.rsp", SearchOption.AllDirectories)
        .Where(x => _nistRegexFilter.IsMatch(Path.GetFileNameWithoutExtension(x)));

    foreach (var filePath in files)
    {
        await ProcessNistFileAsync(filePath);
    }
}


async Task ProcessNistFileAsync(string filePath)
{
    var fileLines = (await File.ReadAllLinesAsync(filePath))
        .Where(x => !x.StartsWith('#'))
        .Where(x => !x.StartsWith("[ENCRYPT]"));

    var fileContent = string.Join('\n', fileLines).Trim();
    while (fileContent.IndexOf("\n\n\n") != -1)
    {
        fileContent = fileContent.Replace("\n\n\n", "\n\n");
    }

    var entryGroups = fileContent.Split("[DECRYPT]", StringSplitOptions.RemoveEmptyEntries);

    var encryptEntries = entryGroups[0].Trim().Split("\n\n");
    var decryptEntries = entryGroups[1].Trim().Split("\n\n");

    var offset = Directory.GetCurrentDirectory().Length + 1;

    var encryptLabel = $"{filePath[offset..]}.ENCRYPT";
    foreach (var encryptEntry in encryptEntries)
    {
        ProcessEncryptEntry(encryptLabel, encryptEntry);
    }

    var decryptLabel = $"{filePath[offset..]}.DECRYPT";
    foreach (var decryptEntry in decryptEntries)
    {
        ProcessDecryptEntry(decryptLabel, decryptEntry);
    }
}

void ProcessEncryptEntry(string label, string textEntry)
{
    var entry = ParseNistEntry(textEntry);
    Console.Write($"{label}[{entry.Count}] = ");

    var output = _aesEncrypter.Encrypt(entry.Input, entry.Key, entry.IV);

    if (output.Length != entry.Output.Length)
    {
        Console.WriteLine("FALHA");
        return;
    }

    if (entry.Output.Zip(output).Any(x => x.First != x.Second))
    {
        Console.WriteLine("FALHA");
        return;
    }

    Console.WriteLine("SUCESSO");
}

void ProcessDecryptEntry(string label, string textEntry)
{
    var entry = ParseNistEntry(textEntry);
    Console.Write($"{label}[{entry.Count}] = ");

    var output = _aesEncrypter.Decrypt(entry.Input, entry.Key, entry.IV);

    if (output.Length != entry.Output.Length)
    {
        Console.WriteLine("FALHA");
        return;
    }

    if (entry.Output.Zip(output).Any(x => x.First != x.Second))
    {
        Console.WriteLine("FALHA");
        return;
    }

    Console.WriteLine("SUCESSO");
}

NistEntry ParseNistEntry(string entry)
{
    var match = _nistEntryRegex.Match(entry);

    if (!match.Success)
    {
        throw new UnreachableException("Falha ao processar arquivo NIST");
    }

    return new NistEntry
    {
        Count = uint.Parse(match.Groups["count"].Value),
        Key = Convert.FromHexString(match.Groups["key"].Value),
        IV = Convert.FromHexString(match.Groups["iv"].Value),
        Input = Convert.FromHexString(match.Groups["input"].Value),
        Output = Convert.FromHexString(match.Groups["output"].Value)
    };
}

byte[] DerivePassword(string password, byte[] salt)
{
    var passwordBytes = Encoding.UTF8.GetBytes(password);

    var derivedKey = _pbkdf2.DeriveKey(passwordBytes, salt, 100_000, 32);

    return derivedKey;
}

struct NistEntry
{
    public uint Count { get; set; }
    public byte[] Key { get; set; }
    public byte[] IV { get; set; }
    public byte[] Input { get; set; }
    public byte[] Output { get; set; }
}
