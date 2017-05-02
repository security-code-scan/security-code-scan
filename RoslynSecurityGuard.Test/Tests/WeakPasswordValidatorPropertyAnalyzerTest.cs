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

		/// <summary>
		/// Indicates which references are needed for the code segments to compile
		/// </summary>
		/// <returns>An array containing the different references required for the code segments to compile</returns>
		protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
		{
			return new[] { MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
				MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location) };
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
							pwdv.RequireNonLetterOrDigit = true;
							pwdv.RequireDigit = true;

							return View();
						}
					}
				}";
			
			VerifyCSharpDiagnostic(test);
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
								RequireNonLetterOrDigit = true,
								RequireDigit = true,
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

			VerifyCSharpDiagnostic(test);
		}

		/// <summary>
		/// Test case where some properties are set outside of the constructor
		/// </summary>
		[TestMethod]
		public void PasswordValidatorOutOfDeclarationOK()
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
							};
							pwdv.RequireNonLetterOrDigit = true;
							pwdv.RequireDigit = true;

							return View();
						}
					}
				}";
						
			VerifyCSharpDiagnostic(test);
		}

		/// <summary>
		/// Test case where the PasswordValidator doesn't have enough properties set
		/// </summary>
		[TestMethod]
		public void PasswordValidatorNotEnoughProperties()
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
							};
							pwdv.RequireDigit = true;

							return View();
						}
					}
				}";

			var expected = new DiagnosticResult
			{
				Id = "SG0033",
				Severity = DiagnosticSeverity.Warning
			};

			VerifyCSharpDiagnostic(test, expected);
		}

		/// <summary>
		/// Test case where the RequiredLength isn't set
		/// </summary>
		[TestMethod]
		public void PasswordValidatorNoRequiredLengthProperty()
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
int test1 = 2;
							PasswordValidator pwdv = new PasswordValidator
							{
								RequireNonLetterOrDigit = true,
								RequireDigit = true,
								RequireLowercase = true,
								RequireUppercase = true,						
							};
int test2 = 3;
							return View();
						}
					}
				}";

			var expected = new DiagnosticResult
			{
				Id = "SG0034",
				Severity = DiagnosticSeverity.Warning
			};

			VerifyCSharpDiagnostic(test, expected);
		}
	}
}
