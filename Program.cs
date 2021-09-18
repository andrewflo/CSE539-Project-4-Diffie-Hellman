using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace P3
{
    class Program
    {
        // dotnet run "A2 2D 93 61 7F DC 0D 8E C6 3E A7 74 51 1B 24 B2" 251 465 255 1311 2101864342 8995936589171851885163650660432521853327227178155593274584417851704581358902 "F2 2C 95 FC 6B 98 BE 40 AE AD 9C 07 20 3B B3 9F F8 2F 6D 2D 69 D6 5D 40 0A 75 45 80 45 F2 DE C8 6E C0 FF 33 A4 97 8A AF 4A CD 6E 50 86 AA 3E DF" AfYw7Z6RzU9ZaGUloPhH3QpfA1AXWxnCGAXAwk3f6MoTx
        // uUNX8P03U3J91XsjCqOJ0LVqt4I4B2ZqEBfX1gCGBH4hH,3D E9 B7 31 42 D7 54 D8 96 12 C9 97 01 12 78 F7 A2 4F 69 1A FF F4 42 99 13 A1 BD 73 52 E5 48 63 33 7A 39 BF C5 25 AD 53 26 53 0D E4 81 51 D1 3E

        static void Main(string[] args)
        {
            // Input args
            byte[] IV = get_bytes_from_string(args[0]);
            int N_e = int.Parse(args[3]);
            int N_c = int.Parse(args[4]);
            int x = int.Parse(args[5]);
            BigInteger gy = BigInteger.Parse(args[6]);
            byte[] C = get_bytes_from_string(args[7]);
            string P = args[8];

            // Compute key
            BigInteger N = BigInteger.Subtract(BigInteger.Pow(2, N_e), N_c);
            BigInteger key = BigInteger.ModPow(gy, x, N);

            string decryptedCipherBytes = Decrypt(C, key.ToByteArray(), IV);
            byte[] encryptedPlainText = Encrypt(P, key.ToByteArray(), IV);

            Console.WriteLine("{0},{1}", decryptedCipherBytes, BitConverter.ToString(encryptedPlainText).Replace("-", " "));
        }

        private static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }

            return encrypted;
        }

        private static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);

                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }

            return plaintext;
        }

        private static byte[] get_bytes_from_string(string input)
        {
            var input_split = input.Split(' ');
            byte[] inputBytes = new byte[input_split.Length];
            int i = 0;
            foreach (string item in input_split)
            {
                inputBytes.SetValue(Convert.ToByte(item, 16), i);
                i++;
            }
            return inputBytes;
        }
    }
}