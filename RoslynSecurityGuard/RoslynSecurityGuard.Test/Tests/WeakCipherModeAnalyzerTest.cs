using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class WeakCipherModeAnalyzerTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new WeakCipherModeAnalyzer();
        }

        [TestMethod]
        public void WeakCipherModeECB()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


class WeakCipherMode
    {

        public static string EncryptECB(string decryptedString)
        {
            DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider();
            desProvider.Mode = CipherMode.ECB;
            desProvider.Padding = PaddingMode.PKCS7;
            desProvider.Key = Encoding.ASCII.GetBytes('d66cf8');
            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.Default.GetBytes(decryptedString);
                    cs.Write(data, 0, data.Length);
                    return Convert.ToBase64String(stream.ToArray());
                }
            }
        }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0012",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void WeakCipherModeOFB()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


class WeakCipherMode
    {

        public static string EncryptOFB(string decryptedString)
        {
            DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider();
            desProvider.Mode = CipherMode.OFB;
            desProvider.Padding = PaddingMode.PKCS7;
            desProvider.Key = Encoding.ASCII.GetBytes('e5d66cf8');
            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.Default.GetBytes(decryptedString);
                    cs.Write(data, 0, data.Length);
                    return Convert.ToBase64String(stream.ToArray());
                }
            }
        }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0012",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyCSharpDiagnostic(test);
        }

    }
}
