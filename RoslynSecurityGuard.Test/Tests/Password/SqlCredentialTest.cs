using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Security;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Password
{
    [TestClass]
    public class SqlCredentialTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }


        public void sandbox()
        {
            SecureString sec = new SecureString();
            string pwd = "abc123";
            pwd.ToCharArray().ToList().ForEach(c => sec.AppendChar(c));
            /* and now : seal the deal */
            sec.MakeReadOnly();

            SqlCredential cred = new SqlCredential("test", sec);
        }
    }
}
