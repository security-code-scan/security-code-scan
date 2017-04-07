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
	/// <summary>
	/// Class used to test the validations on the PasswordValidator.
	/// </summary>
	[TestClass]
	public class WeakPasswordValidatorAnalyzerTest : DiagnosticVerifier
	{
		/// <summary>
		/// Sets which analyzers are needed for the tests.
		/// </summary>
		/// <returns>Array containing the different analyzers required for the tests.</returns>
		protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
		{
			return new[] { new WeakPasswordValidatorAnalyzer() };
		}

		/// <summary>
		/// Indicates which references are needed to compile the code.
		/// </summary>
		/// <returns>Array containing the different references needed for the code to compile.</returns>
		protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
		{
			return new[] { MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location) };
		}

		/// <summary>
		/// Test case where the RequiredLength field is too small inside the declaration.
		/// </summary>
		[TestMethod]
		public void PasswordValidatorDeclarationTooSmall()
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

		/// <summary>
		/// Test case where the RequiredLength field is too small but the value is affected outside of the declaration.
		/// </summary>
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

							pwdv.RequiredLength = " + (Constants.PasswordValidatorRequiredLength - 1) + @";

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

		/// <summary>
		/// Test case where the RequiredLength field has an accepted value.
		/// </summary>
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
								RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @",
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

			VerifyCSharpDiagnostic(test);
		}

		/// <summary>
		/// Test case where the RequiredLength field's value is set by a variable.
		/// However the value of the variable is not tested.
		/// </summary>
		[TestMethod]
		public void PasswordValidatorDeclarationWithVariable()
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
							int reqLen = " + Constants.PasswordValidatorRequiredLength + @";

							PasswordValidator pwdv = new PasswordValidator
							{
								RequiredLength = reqLen,
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

			VerifyCSharpDiagnostic(test);
		}
	}
}



