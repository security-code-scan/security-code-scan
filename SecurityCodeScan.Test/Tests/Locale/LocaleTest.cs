using System;
using Microsoft.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Test.Locale
{
    [TestClass]
    public class LocaleTest
    {
        [TestMethod]
        public void LoadDiagnosticLocale()
        {
            DiagnosticDescriptor desc = LocaleUtil.GetDescriptor("SCS0001");
            Console.WriteLine("Description: " + desc.Description);
        }
    }
}
