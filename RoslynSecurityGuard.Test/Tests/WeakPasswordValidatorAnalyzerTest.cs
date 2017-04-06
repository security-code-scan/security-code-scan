using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TestHelper;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers;
using Microsoft.CodeAnalysis;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;

namespace RoslynSecurityGuard.Test.Tests
{
	[TestClass]
	public class WeakPasswordValidatorAnalyzerTest : DiagnosticVerifier
	{
		protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
		{
			return new[] { new WeakPasswordValidatorAnalyzer() };
		}

		protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
		{
			return new[] { MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location) };
		}

		[TestMethod]
		public void PasswordValidatorDeclarationTooShort()
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
								RequiredLength = 7,
								RequireNonLetterOrDigit = true,
								RequireDigit = true,
								RequireLowercase = true,
								RequireUppercase = true,
							};

							return View();
						}
					}
				}";

			var expected = new DiagnosticResult
			{
				Id = "SG0032",
				Severity = DiagnosticSeverity.Warning
			};

			VerifyCSharpDiagnostic(test, expected);
		}

		[TestMethod]
		public void PasswordValidatorTooShort()
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
				
							};

							pwdv.RequiredLength = 6;

							return View();
						}
					}
				}";

			var expected = new DiagnosticResult
			{
				Id = "SG0032",
				Severity = DiagnosticSeverity.Warning
			};

			VerifyCSharpDiagnostic(test, expected);
		}
	}
}



