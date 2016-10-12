using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using ShopifyMultipassTokenGenerator.Models;

namespace ShopifyMultipassTokenGenerator
{
    public sealed class ShopifyMultipass
    {
        private readonly string secret;
        private readonly string domain;

        public ShopifyMultipass(string secret, string domain)
        {
            if (string.IsNullOrEmpty(secret))
                throw new ArgumentNullException("secret");

            if (string.IsNullOrEmpty(domain))
                throw new ArgumentNullException("domain", "Please specify the shopify domain.");

            this.secret = secret;
            this.domain = domain;
        }

        public string Process(string customerJson)
        {
            if (string.IsNullOrEmpty(customerJson))
                throw new ArgumentNullException("input", "Customer object cannot be null.");


            var theHash = GenerateSHA256();

            ArraySegment<byte> encryptionKeyArraySegmenet = new ArraySegment<byte>(theHash, 0, 16);
            ArraySegment<byte> signatureKeyArraySegmenet = new ArraySegment<byte>(theHash, 16, 16);

            var encryptionKey = encryptionKeyArraySegmenet.ToArray();
            var signatureKey = signatureKeyArraySegmenet.ToArray();
            
            //generate random 16 bytes for Init Vactor
            var iv = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(iv);

            //Generate Cipher using AES-128-CBC algo and concat Init Vector with this.
            var cipherData = EncryptStringToBytes(customerJson, encryptionKey, iv);
            var cipher = Combine(iv, cipherData);

            //Generate signature of Cipher
            HMACSHA256 hasher = new HMACSHA256(signatureKey);
            byte[] sing = hasher.ComputeHash(cipher);

            //append signature to cipher and convert it to URL safe base64 string
            var token = Convert.ToBase64String(Combine(cipher, sing)).Replace("+", "-").Replace("/", "_");

            //_log.InfoFormat("Multipass token => {0}", token);

            var redirectUrl = GetMultipassRedirectUrl(token);

            return redirectUrl;
        }

        /// <summary>
        /// Convert your data to multipass token and get redirect url for shopify mutipass
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private string GetMultipassRedirectUrl(string token)
        {
            //build redirect url
            return string.Format("https://{0}/account/login/multipass/{1}", this.domain, token);
        }

        public string SendToken(string token)
        {
            var url = GetMultipassRedirectUrl(token);

            WebClient webClient = new WebClient();
            var response = webClient.DownloadString(url);

            return response;
        }

        private byte[] GenerateSHA256()
        {
            SHA256 sha256 = SHA256.Create();
            var theHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(this.secret));


            return theHash;
        }


        private byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;


            using (var aes = Aes.Create())
            {
                aes.Key = Key;
                aes.Mode = CipherMode.CBC;
                aes.IV = IV;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                return encrypted;

            }
        }


        /// <summary>
        /// for merging two bytes arrays
        /// </summary>
        /// <param name="a1">First array</param>
        /// <param name="a2">Second array</param>
        /// <returns></returns>
        private byte[] Combine(byte[] a1, byte[] a2)
        {
            byte[] ret = new byte[a1.Length + a2.Length];
            Array.Copy(a1, 0, ret, 0, a1.Length);
            Array.Copy(a2, 0, ret, a1.Length, a2.Length);
            return ret;
        }
    }
}
