using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Linq;

namespace DataProtection
{
    public class AesEncryption
    {
        internal AesEncryption() { }

        public string Encrypt(string plainText, string key, string salt)
        {
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(saltBytes, 0, saltBytes.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public string Decrypt(string cipherText, string key, string salt)
        {
            byte[] iv = new byte[16];
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            byte[] buffer = Convert.FromBase64String(cipherText);

            byte[] extractedSalt = new byte[saltBytes.Length];
            Array.Copy(buffer, 0, extractedSalt, 0, extractedSalt.Length);

            if (!saltBytes.SequenceEqual(extractedSalt))
                throw new ArgumentException("Provided salt does not match the salt in the encrypted data.");

            byte[] encryptedData = new byte[buffer.Length - extractedSalt.Length];
            Array.Copy(buffer, extractedSalt.Length, encryptedData, 0, encryptedData.Length);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(encryptedData))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
