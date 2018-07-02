using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class MvcCsrfTokenAnalyzer : CsrfTokenAnalyzer
    {
        public MvcCsrfTokenAnalyzer() : base("System.Web.Mvc", "System.Web.Mvc") { }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class CoreCsrfTokenAnalyzer : CsrfTokenAnalyzer
    {
        public CoreCsrfTokenAnalyzer() : base("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Authorization") { }
    }

    public abstract class CsrfTokenAnalyzer : DiagnosticAnalyzer
    {
        public const            string                               DiagnosticId = "SCS0016";
        private static readonly DiagnosticDescriptor                 Rule         = LocaleUtil.GetDescriptor(DiagnosticId);
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        protected CsrfTokenAnalyzer(string nameSpace, string allowAnonymousNamespace)
        {
            //99% of the occurrences will be HttpPost.. but here are some additional HTTP methods
            //https://msdn.microsoft.com/en-us/library/system.web.mvc.actionmethodselectorattribute(v=vs.118).aspx
            Namespace = nameSpace;
            MethodsHttp = new List<string>
            {
                $"{nameSpace}.HttpPostAttribute",
                $"{nameSpace}.HttpPutAttribute",
                $"{nameSpace}.HttpDeleteAttribute",
                $"{nameSpace}.HttpPatchAttribute",
            };

            AnonymousAttribute   = $"{allowAnonymousNamespace}.AllowAnonymousAttribute";
        }

        private readonly string       Namespace;
        private readonly string       AnonymousAttribute;
        private readonly List<string> MethodsHttp;

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSymbolAction(VisitMethods, SymbolKind.Method);
        }

        private bool HasAntiForgeryToken(AttributeData attributeData, string antiForgeryAttribute)
        {
            return attributeData.AttributeClass.ToString() == antiForgeryAttribute;
        }

        private bool HasAnonymousAttribute(AttributeData attributeData)
        {
            return attributeData.AttributeClass.ToString() == AnonymousAttribute;
        }

        private void VisitMethods(SymbolAnalysisContext ctx)
        {
            var symbol = (IMethodSymbol)ctx.Symbol;

            if (!symbol.HasDerivedMethodAttribute(attributeData =>
                                                      MethodsHttp.Contains(attributeData.AttributeClass.ToString())))
                return;

            if (symbol.HasDerivedMethodAttribute(HasAnonymousAttribute) ||
                symbol.ReceiverType.HasDerivedClassAttribute(HasAnonymousAttribute))
                return;

            var antiforgeryAttributeExists = false;
            var antiForgeryAttributes = ConfigurationManager.Instance.GetAntiCsrfAttributes(ctx.Options.AdditionalFiles, Namespace);
            foreach (var antiForgeryAttribute in antiForgeryAttributes)
            {
                if (symbol.ReceiverType.HasDerivedClassAttribute(attributeData => HasAntiForgeryToken(attributeData, antiForgeryAttribute)) ||
                    symbol.HasDerivedMethodAttribute(attributeData => HasAntiForgeryToken(attributeData, antiForgeryAttribute)))
                {
                    antiforgeryAttributeExists = true;
                    break;
                }
            }

            if (!antiforgeryAttributeExists)
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, symbol.Locations[0]));
        }
    }
}
