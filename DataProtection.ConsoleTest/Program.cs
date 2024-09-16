using System.Security.Cryptography;
using System;

namespace DataProtection.ConsoleTest
{
    internal class Program
    {
        private const string DataToEncrypt = "Not encrypted sensitive data to encrypt.";

        private static ConsoleColor _defaultForegroundColor = Console.ForegroundColor;

        static void Main(string[] args)
        {
            AesEncryptionTest();
            RsaEncryptionTest();

            Console.ReadKey();
        }

        private static void AesEncryptionTest()
        {
            Console.WriteLine("AES Encryption test:");
            string key = "0123456789abcdefghijklmnopqrstuv";
            string salt = "my salt data";

            string encrypted = Encryption.Aes.Encrypt(DataToEncrypt, key, salt);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Encrypted data: {encrypted}");
            Console.ForegroundColor = _defaultForegroundColor;

            string decrypted = Encryption.Aes.Decrypt(encrypted, key, salt);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Decrypted data: {decrypted}");
            Console.ForegroundColor = _defaultForegroundColor;

            Console.WriteLine("----------------------------------------");
            Console.WriteLine();
        }

        private static void RsaEncryptionTest()
        {
            Console.WriteLine("RSA Encryption test:");

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);
                
                string encrypted = Encryption.Rsa.Encrypt(DataToEncrypt, publicKey);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Encrypted data: {encrypted}");
                Console.ForegroundColor = _defaultForegroundColor;

                string decrypted = Encryption.Rsa.Decrypt(encrypted, privateKey);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Decrypted data: {decrypted}");
                Console.ForegroundColor = _defaultForegroundColor;
            }
        }
    }
}
