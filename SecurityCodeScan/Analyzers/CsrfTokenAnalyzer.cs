using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

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

            AnonymousAttribute = $"{allowAnonymousNamespace}.AllowAnonymousAttribute";
            NonActionAttribute = $"{nameSpace}.NonActionAttribute";
            Controller         = $"{nameSpace}.Controller";
        }

        private readonly string       Controller;
        private readonly string       NonActionAttribute;
        private readonly string       Namespace;
        private readonly string       AnonymousAttribute;
        private readonly List<string> MethodsHttp;

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSymbolAction(VisitClass, SymbolKind.NamedType);
        }

        private bool HasAntiForgeryToken(AttributeData attributeData, string antiForgeryAttribute)
        {
            return attributeData.AttributeClass.ToString() == antiForgeryAttribute;
        }

        private bool HasAnonymousAttribute(AttributeData attributeData)
        {
            return attributeData.AttributeClass.ToString() == AnonymousAttribute;
        }

        private void VisitClass(SymbolAnalysisContext ctx)
        {
            var classSymbol = (ITypeSymbol)ctx.Symbol;
            if (!classSymbol.IsDerivedFrom(Controller))
                return;

            var antiForgeryAttributes = ConfigurationManager.Instance.GetAntiCsrfAttributes(ctx.Options.AdditionalFiles, Namespace);

            foreach (var member in classSymbol.GetMembers())
            {
                if (!(member is IMethodSymbol methodSymbol))
                    continue;

                if (!methodSymbol.HasDerivedMethodAttribute(attributeData =>
                                                                MethodsHttp.Contains(attributeData.AttributeClass.ToString())))
                    continue;

                if (methodSymbol.HasDerivedMethodAttribute(attributeData => attributeData.AttributeClass.ToString() == NonActionAttribute))
                    continue;

                if (methodSymbol.HasDerivedMethodAttribute(HasAnonymousAttribute) ||
                    methodSymbol.ReceiverType.HasDerivedClassAttribute(HasAnonymousAttribute))
                    continue;

                if (!AntiforgeryAttributeExists(methodSymbol, antiForgeryAttributes))
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, methodSymbol.Locations[0]));
            }
        }

        private bool AntiforgeryAttributeExists(IMethodSymbol methodSymbol, IEnumerable<string> antiForgeryAttributes)
        {
            foreach (var antiForgeryAttribute in antiForgeryAttributes)
            {
                if (methodSymbol.ReceiverType.HasDerivedClassAttribute(attributeData =>
                                                                           HasAntiForgeryToken(attributeData, antiForgeryAttribute)) ||
                    methodSymbol.HasDerivedMethodAttribute(attributeData => HasAntiForgeryToken(attributeData, antiForgeryAttribute)))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
