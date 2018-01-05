using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

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
            SyntaxNode node;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node = ctx.Node as CSharpSyntax.MethodDeclarationSyntax;
                if (node == null)
                    return;
            }
            else
            {
                node = ctx.Node as VBSyntax.MethodBlockSyntax;
                if (node == null)
                    return;
            }

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

            ctx.ReportDiagnostic(Diagnostic.Create(Rule, node.GetLocation()));
        }
    }
}
