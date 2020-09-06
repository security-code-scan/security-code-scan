using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WeakCipherAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new WeakCipherAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new WeakCipherAnalyzerVisualBasic() };
        }

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0010",
            Severity = DiagnosticSeverity.Warning
        };

        [TestCategory("Safe")]
        [TestMethod]
        public async Task WeakCipherFalsePositive()
        {
            var cSharpTest = @"
using System.IO;
using System.Security.Cryptography;

public class WeakCipherAlgorithm
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
    }
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Security.Cryptography

Public Class WeakCipherAlgorithm
    Private Shared Sub EncryptTextToFileTripleDES(Data As String, FileName As String, Key As Byte(), IV As Byte())
        ' Create or open the specified file.
        Dim fStream As FileStream = File.Open(FileName, FileMode.OpenOrCreate)

        ' Create a new TripleDES object.
        Dim tripleDESalg As TripleDES = TripleDES.Create()

        ' Create a CryptoStream using the FileStream  
        ' and the passed key and initialization vector (IV).
        Dim cStream As New CryptoStream(fStream, tripleDESalg.CreateEncryptor(Key, IV), CryptoStreamMode.Write)

        ' Create a StreamWriter using the CryptoStream.
        Dim sWriter As New StreamWriter(cStream)

        ' Write the data to the stream  
        ' to encrypt it.
        sWriter.WriteLine(Data)

        ' Close the streams and 
        ' close the file.
        sWriter.Close()
        cStream.Close()
        fStream.Close()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task WeakCipherVulnerableDES()
        {
            var cSharpTest = @"
using System.IO;
using System.Security.Cryptography;

public class WeakCipherAlgorithm
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
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Security.Cryptography

Public Class WeakCipherAlgorithm

    Private Shared Function EncryptDataDES(inName As String, outName As String, desKey As Byte(), desIV As Byte(), Data As String) As Byte()
        Dim zeroIV As Byte() = New Byte() {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
        Dim key As Byte() = New Byte() {1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}
        ' Create a new DES object to generate a key 
        ' and initialization vector (IV).
        Dim DESalg As DES = DES.Create()

        ' Create a string to encrypt. 
        Dim encrypted As Byte()
        Dim encryptor As ICryptoTransform = DESalg.CreateEncryptor(key, zeroIV)

        ' Create the streams used for encryption. 
        Using msEncrypt As New MemoryStream()
            Using csEncrypt As New CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)
                Using swEncrypt As New StreamWriter(csEncrypt)

                    'Write all data to the stream.
                    swEncrypt.Write(Data)
                End Using
                encrypted = msEncrypt.ToArray()
                Return encrypted
            End Using
        End Using
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task WeakCipherVulnerableRC2()
        {
            var cSharpTest = @"
using System.IO;
using System.Security.Cryptography;

public class WeakCipherAlgorithm
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
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Security.Cryptography

Public Class WeakCipherAlgorithm

    Private Shared Function EncryptDataRC2(inName As String, outName As String, desKey As Byte(), desIV As Byte(), Data As String) As Byte()
        Dim zeroIV As Byte() = New Byte() {0, 0, 0, 0, 0, 0, _
            0, 0, 0, 0, 0, 0, _
            0, 0, 0, 0}
        Dim key As Byte() = New Byte() {1, 2, 3, 4, 5, 6, _
            7, 8, 0, 0, 0, 0, _
            0, 0, 0, 0}
        ' Create a new RC2 object to generate a key 
        ' and initialization vector (IV).
        Dim RC2alg As RC2 = RC2.Create()

        ' Create a string to encrypt. 
        Dim encrypted As Byte()

        Dim encryptor As ICryptoTransform = RC2alg.CreateEncryptor(key, zeroIV)

        ' Create the streams used for encryption. 
        Using msEncrypt As New MemoryStream()
            Using csEncrypt As New CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)
                Using swEncrypt As New StreamWriter(csEncrypt)

                    'Write all data to the stream.
                    swEncrypt.Write(Data)
                End Using
                encrypted = msEncrypt.ToArray()
                Return encrypted
            End Using
        End Using
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task WeakCipherVulnerableDES2()
        {
            var cSharpTest = @"
using System.IO;
using System.Security.Cryptography;

public class WeakCipherAlgorithm
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
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Security.Cryptography

Public Class WeakCipherAlgorithm
    Private Shared Sub EncryptData(inName As String, outName As String, desKey As Byte(), desIV As Byte())
        'Create the file streams to handle the input and output files.
        Dim fin As New FileStream(inName, FileMode.Open, FileAccess.Read)
        Dim fout As New FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write)
        fout.SetLength(0)

        'Create variables to help with read and write. 
        Dim bin As Byte() = New Byte(99) {}
        'This is intermediate storage for the encryption. 
        Dim rdlen As Long = 0
        'This is the total number of bytes written. 
        Dim totlen As Long = fin.Length
        'This is the total length of the input file. 
        Dim len As Integer
        'This is the number of bytes to be written at a time.
        Dim des As DES = New DESCryptoServiceProvider()
        Dim encStream As New CryptoStream(fout, des.CreateEncryptor(desKey, desIV), CryptoStreamMode.Write)


        'Read from the input file, then encrypt and write to the output file. 
        While rdlen < totlen
            len = fin.Read(bin, 0, 100)
            encStream.Write(bin, 0, len)
            rdlen = rdlen + len
        End While

        encStream.Close()
        fout.Close()
        fin.Close()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task WeakCipherVulnerableRC2_2()
        {
            var cSharpTest = @"
using System.IO;
using System.Security.Cryptography;

public class WeakCipherAlgorithm
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
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Security.Cryptography

Public Class WeakCipherAlgorithm
    Private Shared Sub EncryptData(inName As String, outName As String, rc2Key As Byte(), rc2IV As Byte())
        'Create the file streams to handle the input and output files.
        Dim fin As New FileStream(inName, FileMode.Open, FileAccess.Read)
        Dim fout As New FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write)
        fout.SetLength(0)

        'Create variables to help with read and write. 
        Dim bin As Byte() = New Byte(99) {}
        'This is intermediate storage for the encryption. 
        Dim rdlen As Long = 0
        'This is the total number of bytes written. 
        Dim totlen As Long = fin.Length
        'This is the total length of the input file. 
        Dim len As Integer
        'This is the number of bytes to be written at a time.
        Dim rc2 As RC2 = New RC2CryptoServiceProvider()
        Dim encStream As New CryptoStream(fout, rc2.CreateEncryptor(rc2Key, rc2IV), CryptoStreamMode.Write)


        'Read from the input file, then encrypt and write to the output file. 
        While rdlen < totlen
            len = fin.Read(bin, 0, 100)
            encStream.Write(bin, 0, len)
            rdlen = rdlen + len
        End While

        encStream.Close()
        fout.Close()
        fin.Close()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task GivenAliasDirective_DetectDiagnostic()
        {
            var cSharpTest = @"
using System.IO;
using System.Security.Cryptography;
using CS = System.Security.Cryptography.CryptoStream;

public class WeakCipherAlgorithm
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
        CS encStream = new CS(fout, des.CreateEncryptor(desKey, desIV), CryptoStreamMode.Write);


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
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Security.Cryptography
Imports CS = System.Security.Cryptography.CryptoStream

Public Class WeakCipherAlgorithm
    Private Shared Sub EncryptData(inName As String, outName As String, desKey As Byte(), desIV As Byte())
        'Create the file streams to handle the input and output files.
        Dim fin As New FileStream(inName, FileMode.Open, FileAccess.Read)
        Dim fout As New FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write)
        fout.SetLength(0)

        'Create variables to help with read and write. 
        Dim bin As Byte() = New Byte(99) {}
        'This is intermediate storage for the encryption. 
        Dim rdlen As Long = 0
        'This is the total number of bytes written. 
        Dim totlen As Long = fin.Length
        'This is the total length of the input file. 
        Dim len As Integer
        'This is the number of bytes to be written at a time.
        Dim des As DES = New DESCryptoServiceProvider()
        Dim encStream As New CS(fout, des.CreateEncryptor(desKey, desIV), CryptoStreamMode.Write)


        'Read from the input file, then encrypt and write to the output file. 
        While rdlen < totlen
            len = fin.Read(bin, 0, 100)
            encStream.Write(bin, 0, len)
            rdlen = rdlen + len
        End While

        encStream.Close()
        fout.Close()
        fin.Close()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

    }
}
