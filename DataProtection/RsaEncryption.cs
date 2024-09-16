using System.Security.Cryptography;
using System.Text;
using System;

namespace DataProtection
{
    public class RsaEncryption
    {
        internal RsaEncryption() { }

        public string Encrypt(string plainText, RSAParameters publicKey)
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                encryptedData = rsa.Encrypt(dataToEncrypt, true);
            }

            return Convert.ToBase64String(encryptedData);
        }

        public string Decrypt(string cipherText, RSAParameters privateKey)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(cipherText);
            byte[] decryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                decryptedData = rsa.Decrypt(dataToDecrypt, true);
            }

            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
