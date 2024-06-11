namespace DataProtection
{
    public class Encryption
    {
        public static AesEncryption Aes { get; } = new AesEncryption();
        public static RsaEncryption Rsa { get; } = new RsaEncryption();
    }
}
