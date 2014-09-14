using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetSecHomework1
{
    /// <summary>
    /// Author: Taylor Stapleton
    /// Class: Network Security
    /// Assignment: Homework 1
    /// Year: 2014
    /// </summary>
    class Program
    {
        #region main method
        static void Main(string[] args)
        {
            
            byte[] message = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };

            byte[] key =     new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

            List<string> outputLines = new List<string>();

            #region round one

            printBytes("first input", message, ref outputLines);

            printBytes("key", key, ref outputLines);

            printBytes("", new byte[0], ref outputLines);

            Dictionary<byte, byte>[] substitutionEncryptionTables = new Dictionary<byte, byte>[8];
            Dictionary<byte, byte>[] substitutionDecryptionTables = new Dictionary<byte, byte>[8];

            generateTables(ref substitutionEncryptionTables, ref substitutionDecryptionTables);

            byte[] encryptedMessage = encryptMessage(message, key, substitutionEncryptionTables, ref outputLines);

            printBytes("", new byte[0], ref outputLines);

            byte[] decryptedMessage = decryptMessage(encryptedMessage, key, substitutionDecryptionTables, ref outputLines);

            printBytes("first decrypted message", message, ref outputLines);
            #endregion

            printBytes("", new byte[0], ref outputLines);
            printBytes("", new byte[0], ref outputLines);
            printBytes("", new byte[0], ref outputLines);
            printBytes("", new byte[0], ref outputLines);

            #region round two
            message = new byte[] { 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };

            printBytes("", new byte[0], ref outputLines);

            printBytes("second input", message, ref outputLines);

            printBytes("key", key, ref outputLines);

            substitutionEncryptionTables = new Dictionary<byte, byte>[8];
            substitutionDecryptionTables = new Dictionary<byte, byte>[8];

            generateTables(ref substitutionEncryptionTables, ref substitutionDecryptionTables);

            encryptedMessage = encryptMessage(message, key, substitutionEncryptionTables, ref outputLines);

            printBytes("", new byte[0], ref outputLines);

            decryptedMessage = decryptMessage(encryptedMessage, key, substitutionDecryptionTables, ref outputLines);

            printBytes("second decrypted message", message, ref outputLines);

            #endregion

            string cwd = Directory.GetCurrentDirectory();

            cwd += "/EncryptionOutput.txt";

            System.IO.File.WriteAllLines(cwd, outputLines);
  
        }
        #endregion

        #region encryption and decryption
        /// <summary>
        /// encrypt a message
        /// </summary>
        /// <param name="message">the message to encrypt</param>
        /// <param name="key">the key for encryption</param>
        /// <param name="substitutionEncryptionTables">the substitution tables</param>
        /// <param name="outputLines">the container to hold text output</param>
        /// <returns></returns>
        static byte[] encryptMessage(byte[] message, byte[] key, Dictionary<byte, byte>[] substitutionEncryptionTables, ref List<string> outputLines)
        {
            for (int i = 0; i < 16; i++)
            {
                List<byte> xoredBytes = new List<byte>();

                List<byte> substitutedBytes = new List<byte>();

                var messageAndKey = message.Zip(key, (m, k) => new { message = m, key = k });

                foreach (var b in messageAndKey)
                {
                    xoredBytes.Add(xorBytes(b.message, b.key));
                }

                var blockAndTable = xoredBytes.Zip(substitutionEncryptionTables, (b, t) => new { block = b, table = t });

                foreach (var p in blockAndTable)
                {
                    substitutedBytes.Add(subByte(p.table, p.block));
                }

                message = performPermutationLeft(substitutedBytes.ToArray());

                printBytes("encryption round " + i + ":", message, ref outputLines);
            }
            return message;
        }

        /// <summary>
        /// decrypt a message
        /// </summary>
        /// <param name="cipherBlock">the cipher block to be decrypted</param>
        /// <param name="key">key by which to decrypt</param>
        /// <param name="substitutionDecryptionTables">substitution tables</param>
        /// <param name="outputLines">container to hole ouput</param>
        /// <returns></returns>
        static byte[] decryptMessage(byte[] cipherBlock, byte[] key, Dictionary<byte, byte>[] substitutionDecryptionTables, ref List<string> outputLines)
        {
            for (int i = 0; i < 16; i++)
            {
                byte[] unPermutedBits = performPermutationRight(cipherBlock);

                List<byte> unSubstitutedBytes = new List<byte>();

                var blockAndTable = unPermutedBits.Zip(substitutionDecryptionTables, (b, t) => new { block = b, table = t });

                foreach (var p in blockAndTable)
                {
                    unSubstitutedBytes.Add(subByte(p.table, p.block));
                }

                List<byte> unXoredBytes = new List<byte>();

                var messageAndKey = unSubstitutedBytes.Zip(key, (m, k) => new { message = m, key = k });

                foreach (var b in messageAndKey)
                {
                    unXoredBytes.Add(xorBytes(b.message, b.key));
                }
                cipherBlock = unXoredBytes.ToArray();

                printBytes("decryption round " + i + ":", cipherBlock, ref outputLines);
            }
            return cipherBlock;
        }
        #endregion

        #region table generation
        /// <summary>
        /// generates the tables by which random substitution is made
        /// </summary>
        /// <param name="substitutionEncryptionTables">container for encryption tables</param>
        /// <param name="substitutionDecryptionTables">container for decryption tables</param>
        static void generateTables(ref Dictionary<byte,byte>[] substitutionEncryptionTables, ref Dictionary<byte,byte>[] substitutionDecryptionTables)
        {
            for (int i = 0; i < 8; i++)
            {
                substitutionEncryptionTables[i] = new Dictionary<byte, byte>();
                substitutionDecryptionTables[i] = new Dictionary<byte, byte>();
                List<byte> bytesInUse = new List<byte>();
                Random randomGen = new Random();

                while (bytesInUse.Count < 256)
                {
                    byte[] randomBytes = new byte[1];
                    randomGen.NextBytes(randomBytes);
                    if (!bytesInUse.Contains(randomBytes[0]))
                    {
                        bytesInUse.Add(randomBytes[0]);
                    }
                }
                for (int j = 0; j <= 255; j++)
                {
                    substitutionEncryptionTables[i][(byte)j] = bytesInUse[j];
                    substitutionDecryptionTables[i][bytesInUse[j]] = (byte)j;
                    //Console.WriteLine(j);
                }
            }
        }
        #endregion

        #region permutations
        /// <summary>
        /// permutes a byte array one but to the left
        /// </summary>
        /// <param name="message">the bytes to be permuted</param>
        /// <returns></returns>
        static byte[] performPermutationLeft(byte[] message)
        {
            long convertedBits = BitConverter.ToInt64(message, 0);

            long shiftResult = (convertedBits << 1) | (convertedBits >> 63);

            return BitConverter.GetBytes(convertedBits);
        }

        /// <summary>
        /// permutes a byte array one bit to the right
        /// </summary>
        /// <param name="message">the bytes to be permuted</param>
        /// <returns></returns>
        static byte[] performPermutationRight(byte[] message)
        {
            long convertedBits = BitConverter.ToInt64(message, 0);

            long shiftResult = (convertedBits >> 1) | (convertedBits << 63);

            return BitConverter.GetBytes(convertedBits);
        }
        #endregion

        #region helper functions
        /// <summary>
        /// xor two bytes together
        /// </summary>
        /// <param name="a">left byte</param>
        /// <param name="b">right byte</param>
        /// <returns></returns>
        static byte xorBytes(byte a, byte b)
        {
            return (byte)(a ^ b);
        }

        /// <summary>
        /// substitute a single byte
        /// </summary>
        /// <param name="table">the table to look at</param>
        /// <param name="toSub">the byte to substitute</param>
        /// <returns></returns>
        static byte subByte(Dictionary<byte, byte> table, byte toSub)
        {
            byte result;
            table.TryGetValue(toSub, out result);
            return result;
        }

        /// <summary>
        /// pretty print a byte array to the container of output
        /// </summary>
        /// <param name="message">message to be included with the bytes</param>
        /// <param name="toPrint">the message to print</param>
        /// <param name="outputList">the output container</param>
        static void printBytes(string message, byte[] toPrint, ref List<string> outputList)
        {
            string line = message + ": ";
            foreach(byte b in toPrint)
            {
                line += b + " ";
            }
            outputList.Add(line);
        }
        #endregion
    }
}
