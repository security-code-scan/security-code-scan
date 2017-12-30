using Microsoft.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Locale;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityCodeScan.Tests.Locale
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
