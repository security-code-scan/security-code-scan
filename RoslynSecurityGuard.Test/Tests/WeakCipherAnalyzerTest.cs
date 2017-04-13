using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestHelper;
using Microsoft.CodeAnalysis;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class WeakCipherAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakCipherAnalyzer() };
        }

        [TestMethod]
        public async Task WeakCipherFalsePositive()
        {
            var test = @"
using System.IO;
using System.Security.Cryptography;

class WeakCipherAlgorithm
    {
    static void EncryptTextToFileTripleDES(string Data, string FileName, byte[] Key, byte[] IV)
        {
                // Create or open the specified file.
                FileStream fStream = File.Open(FileName, FileMode.OpenOrCreate);

                // Create a new TripleDES object.
                TripleDES tripleDESalg = TripleDES.Create();

                // Create a CryptoStream using the FileStream  
                // and the passed key and initialization vector (IV).
                CryptoStream cStream = new CryptoStream(fStream,
                    tripleDESalg.CreateEncryptor(Key, IV),
                    CryptoStreamMode.Write);

                // Create a StreamWriter using the CryptoStream.
                StreamWriter sWriter = new StreamWriter(cStream);

                // Write the data to the stream  
                // to encrypt it.
                sWriter.WriteLine(Data);

                // Close the streams and 
                // close the file.
                sWriter.Close();
                cStream.Close();
                fStream.Close();
        }
    }";
            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task WeakCipherVulnerableDES()
        {
            var test = @"
using System.IO;
using System.Security.Cryptography;

class WeakCipherAlgorithm
{

        private static byte[] EncryptDataDES(string inName, string outName, byte[] desKey, byte[] desIV, string Data)
        {
            byte[] zeroIV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0 };
            // Create a new DES object to generate a key 
            // and initialization vector (IV).
            DES DESalg = DES.Create();

            // Create a string to encrypt. 
            byte[] encrypted;

            ICryptoTransform encryptor = DESalg.CreateEncryptor(key, zeroIV);

            // Create the streams used for encryption. 
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(Data);
                    }
                    encrypted = msEncrypt.ToArray();
                    return encrypted;
                }
            }
        }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0010",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task WeakCipherVulnerableRC2()
        {
            var test = @"
using System.IO;
using System.Security.Cryptography;

class WeakCipherAlgorithm
{

        private static byte[] EncryptDataRC2(string inName, string outName, byte[] desKey, byte[] desIV, string Data)
        {
            byte[] zeroIV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0 };
            // Create a new RC2 object to generate a key 
            // and initialization vector (IV).
            RC2 RC2alg = RC2.Create();

            // Create a string to encrypt. 
            byte[] encrypted;

            ICryptoTransform encryptor = RC2alg.CreateEncryptor(key, zeroIV);

            // Create the streams used for encryption. 
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(Data);
                    }
                    encrypted = msEncrypt.ToArray();
                    return encrypted;
                }
            }
        }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0010",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task WeakCipherVulnerableDES2()
        {
            var test = @"
using System.IO;
using System.Security.Cryptography;

class WeakCipherAlgorithm
{
    private static void EncryptData(string inName, string outName, byte[] desKey, byte[] desIV)
    {
        //Create the file streams to handle the input and output files.
        FileStream fin = new FileStream(inName, FileMode.Open, FileAccess.Read);
        FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
        fout.SetLength(0);

        //Create variables to help with read and write. 
        byte[] bin = new byte[100]; //This is intermediate storage for the encryption. 
        long rdlen = 0;              //This is the total number of bytes written. 
        long totlen = fin.Length;    //This is the total length of the input file. 
        int len;                     //This is the number of bytes to be written at a time.

        DES des = new DESCryptoServiceProvider();
        CryptoStream encStream = new CryptoStream(fout, des.CreateEncryptor(desKey, desIV), CryptoStreamMode.Write);


        //Read from the input file, then encrypt and write to the output file. 
        while (rdlen < totlen)
        {
            len = fin.Read(bin, 0, 100);
            encStream.Write(bin, 0, len);
            rdlen = rdlen + len;
        }

        encStream.Close();
        fout.Close();
        fin.Close();
    }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0010",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task WeakCipherVulnerableRC2_2()
        {
            var test = @"
using System.IO;
using System.Security.Cryptography;

class WeakCipherAlgorithm
{
    private static void EncryptData(string inName, string outName, byte[] rc2Key, byte[] rc2IV)
    {
        //Create the file streams to handle the input and output files.
        FileStream fin = new FileStream(inName, FileMode.Open, FileAccess.Read);
        FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
        fout.SetLength(0);

        //Create variables to help with read and write. 
        byte[] bin = new byte[100]; //This is intermediate storage for the encryption. 
        long rdlen = 0;              //This is the total number of bytes written. 
        long totlen = fin.Length;    //This is the total length of the input file. 
        int len;                     //This is the number of bytes to be written at a time.

        RC2 rc2 = new RC2CryptoServiceProvider();
        CryptoStream encStream = new CryptoStream(fout, rc2.CreateEncryptor(rc2Key, rc2IV), CryptoStreamMode.Write);


        //Read from the input file, then encrypt and write to the output file. 
        while (rdlen < totlen)
        {
            len = fin.Read(bin, 0, 100);
            encStream.Write(bin, 0, len);
            rdlen = rdlen + len;
        }

        encStream.Close();
        fout.Close();
        fin.Close();
    }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0010",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }
    }
}
