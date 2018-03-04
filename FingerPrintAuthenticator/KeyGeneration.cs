using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Generate and Use RSA key pairs
    /// </summary>
    class KeyGeneration
    {
        /// <summary>
        /// The generated private key
        /// </summary>
        AsymmetricKeyParameter privateKey;
        /// <summary>
        /// The der formatted public key
        /// </summary>
        string derFormat;

        /// <summary>
        /// Check if the key pairs already exists
        /// </summary>
        /// <returns>True if the key pairs exists, otherwise false</returns>
        private bool FSCheck()
        {
            if (!Directory.Exists("certificate"))
            {
                Directory.CreateDirectory("certificate");
                return false;
            }

            return File.Exists("certificate\\private.key") && File.Exists("certificate\\public.key");
        }

        /// <summary>
        /// Save a key pair to the disk
        /// </summary>
        /// <param name="keyPair">Key pair to save</param>
        private void SaveToDisk(AsymmetricCipherKeyPair keyPair)
        {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();
            string serializedPrivate = Convert.ToBase64String(serializedPrivateBytes);

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            string serializedPublic = Convert.ToBase64String(serializedPublicBytes);

            File.WriteAllText("certificate\\public.key", serializedPublic);
            File.WriteAllText("certificate\\private.key", serializedPrivate);
        }

        /// <summary>
        /// Load key pair from the disk
        /// </summary>
        /// <returns>The loaded key pair</returns>
        private AsymmetricCipherKeyPair LoadFromDisk()
        {
            string serializedPublic = File.ReadAllText("certificate\\public.key");
            string serializedPrivate = File.ReadAllText("certificate\\private.key");
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(serializedPrivate));
            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(serializedPublic));
            AsymmetricCipherKeyPair ckp = new AsymmetricCipherKeyPair(publicKey, privateKey);
            return ckp;
        }

        /// <summary>
        /// Create/Load RSA key pairs
        /// </summary>
        public void GenerateKeys()
        {
            AsymmetricCipherKeyPair keyPair;

            if (!FSCheck())
            {
                RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
                generator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
                keyPair = generator.GenerateKeyPair();
                SaveToDisk(keyPair);
            }
            else
            {
                keyPair = LoadFromDisk();
            }

            privateKey = keyPair.Private;
            RsaKeyParameters keyParam = (RsaKeyParameters)keyPair.Public;
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParam);
            derFormat = Convert.ToBase64String(info.GetEncoded());
        }

        /// <summary>
        /// Get the DER public key for the device
        /// </summary>
        /// <returns>The DER public key</returns>
        public string GetDerPublicKey()
        {
            if (derFormat == null) throw new InvalidOperationException("Can't access der formatted key, because keys aren't generated yet!");
            return derFormat;
        }

        /// <summary>
        /// Decrypt data with the public key
        /// </summary>
        /// <param name="dataToDecrypt">The bytes to decryp</param>
        /// <returns>The decrypted bytes</returns>
        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            if (privateKey == null) throw new InvalidOperationException("The key pair is not yet initialized");
            IAsymmetricBlockCipher cipher = new RsaEngine();
            cipher.Init(false, privateKey);
            byte[] decrypted = cipher.ProcessBlock(dataToDecrypt, 0, dataToDecrypt.Length);
            return decrypted;
        }
    }
}
