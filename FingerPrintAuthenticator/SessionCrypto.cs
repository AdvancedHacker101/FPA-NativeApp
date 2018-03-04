﻿using System;
using System.Security.Cryptography;
using System.Text;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Class used for session data encryption/decryption
    /// </summary>
    class SessionCrypto
    {
        /// <summary>
        /// The AES key used for crypto
        /// </summary>
        private byte[] sessKey;
        /// <summary>
        /// The IV used for crypto
        /// </summary>
        private byte[] ivKey;

        /// <summary>
        /// Set the session key and the IV
        /// </summary>
        /// <param name="sessionKey">The session key sent by the device</param>
        public void SetSessionKey(string sessionKey)
        {
            string[] parts = sessionKey.Split('|');
            ivKey = Convert.FromBase64String(parts[0]);
            sessKey = Convert.FromBase64String(parts[1]);
        }

        /// <summary>
        /// SHA256 Hash a String
        /// </summary>
        /// <param name="message">The string to get the hash of</param>
        /// <returns>The base64 encoded hashed value</returns>
        public static string DigestMessage(string message)
        {
            byte[] messageData = Encoding.UTF8.GetBytes(message);
            using (SHA256Managed hash = new SHA256Managed())
            {
                byte[] digestedMessage = hash.ComputeHash(messageData);
                return Convert.ToBase64String(digestedMessage);
            }
        }

        /// <summary>
        /// Decrypt session data from the device
        /// </summary>
        /// <param name="cipherText">The data to decrypt</param>
        /// <returns>The clear text data</returns>
        public byte[] DecryptData(string cipherText)
        {
            using (AesManaged aes = new AesManaged()
            {
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                BlockSize = 128,
                KeySize = 128,
                Key = sessKey,
                IV = ivKey
            })
            {
                ICryptoTransform cipher = aes.CreateDecryptor();
                byte[] message = Convert.FromBase64String(cipherText);
                byte[] data = cipher.TransformFinalBlock(message, 0, message.Length);
                return data;
            }
        }

        /// <summary>
        /// Encrypt session data to the device
        /// </summary>
        /// <param name="clearText">The text to encrypt</param>
        /// <returns>The base64 encoded encrypted value</returns>
        public byte[] EncryptData(byte[] clearText)
        {
            using (AesManaged aes = new AesManaged()
            {
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                BlockSize = 128,
                KeySize = 128,
                Key = sessKey,
                IV = ivKey
            })
            {
                ICryptoTransform cipher = aes.CreateEncryptor();
                byte[] data = cipher.TransformFinalBlock(clearText, 0, clearText.Length);
                return data;
            }
        }
    }
}