using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
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
            MethodsHttp = new List<string>
            {
                $"{nameSpace}.HttpPostAttribute",
                $"{nameSpace}.HttpPutAttribute",
                $"{nameSpace}.HttpDeleteAttribute",
                $"{nameSpace}.HttpPatchAttribute",
            };

            AntiForgeryAttribute = $"{nameSpace}.ValidateAntiForgeryTokenAttribute";
            AnonymousAttribute   = $"{allowAnonymousNamespace}.AllowAnonymousAttribute";
        }

        private readonly string       AntiForgeryAttribute;
        private readonly string       AnonymousAttribute;
        private readonly List<string> MethodsHttp;

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethods, VB.SyntaxKind.SubBlock, VB.SyntaxKind.FunctionBlock);
        }

        private bool HasAntiForgeryToken(AttributeData attributeData)
        {
            return attributeData.AttributeClass.ToString() == AntiForgeryAttribute;
        }

        private bool HasAnonymousAttribute(AttributeData attributeData)
        {
            return attributeData.AttributeClass.ToString() == AnonymousAttribute;
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = (IMethodSymbol)ctx.SemanticModel.GetDeclaredSymbol(ctx.Node);

            if (!symbol.HasDerivedMethodAttribute(attributeData =>
                                                      MethodsHttp.Contains(attributeData.AttributeClass.ToString())))
                return;

            if (symbol.HasDerivedMethodAttribute(HasAnonymousAttribute) ||
                symbol.ReceiverType.HasDerivedClassAttribute(HasAnonymousAttribute))
            {
                return;
            }

            if (symbol.ReceiverType.HasDerivedClassAttribute(HasAntiForgeryToken))
                return;

            if (symbol.HasDerivedMethodAttribute(HasAntiForgeryToken))
                return;

            Location diagnosticsLocation;
            if (ctx.Node is MethodDeclarationSyntax methodDeclaration)
                diagnosticsLocation = methodDeclaration.Identifier.GetLocation();
            else
                diagnosticsLocation = ((MethodBlockSyntax)ctx.Node).SubOrFunctionStatement.Identifier.GetLocation();

            ctx.ReportDiagnostic(Diagnostic.Create(Rule, diagnosticsLocation));
        }
    }
}
