using Microsoft.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Locale;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Tests.Locale
{
    [TestClass]
    public class LocaleTest
    {

        [TestMethod]
        public void LoadDiagnosticLocale()
        {

            DiagnosticDescriptor desc = LocaleUtil.GetDescriptor("SG0001");
            Console.WriteLine("Description: " + desc.Description);


        }
    }
}
