using Microsoft.AspNet.Identity;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
	[TestClass]
	public class WeakPasswordValidatorPropertyAnalyzerTest : DiagnosticVerifier
	{

		protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
		{
			return new DiagnosticAnalyzer[] { new WeakPasswordValidatorPropertyAnalyzer(), new TaintAnalyzer() };
		}

		protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
		{
			return new[] { MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location) };
		}

		[TestMethod]
		public void PasswordValidatorDeclarationOK()
		{
			var test = @"
				using Microsoft.AspNet.Identity;
				using System.Web.Mvc;

				namespace WebApplicationSandbox.Controllers
				{
					public class HomeController : Controller
					{
						public ActionResult Index()
						{
							PasswordValidator pwdv = new PasswordValidator
							{
								RequiredLength = " + (Constants.PasswordValidatorRequiredLength - 1) + @",
								RequireNonLetterOrDigit = true,
								RequireDigit = true,
								RequireLowercase = true,
								RequireUppercase = true,
							};
							pwdv.RequireNonLetterOrDigit = true;
							pwdv.RequireDigit = true;

							return View();
						}
					}
				}";

			//var expected = new DiagnosticResult
			//{
			//	Id = "SG0033",
			//	Severity = DiagnosticSeverity.Warning
			//};

			VerifyCSharpDiagnostic(test);
		}
	}
}
