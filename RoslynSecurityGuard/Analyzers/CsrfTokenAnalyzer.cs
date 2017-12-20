using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using System.Collections.Generic;
using System.Collections.Immutable;

using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class CsrfTokenAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0016";
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        //99% of the occurences will be HttpPost.. but here are some additionnal HTTP methods
        //https://msdn.microsoft.com/en-us/library/system.web.mvc.actionmethodselectorattribute(v=vs.118).aspx
        private readonly List<string> MethodsHttp = new List<string>
        {
            "System.Web.Mvc.HttpPostAttribute",
            "System.Web.Mvc.HttpPutAttribute",
            "System.Web.Mvc.HttpDeleteAttribute",
            "System.Web.Mvc.HttpPatchAttribute",
        };

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethods, VB.SyntaxKind.SubBlock, VB.SyntaxKind.FunctionBlock);
        }

        private bool HasAntiForgeryToken(AttributeData attributeData)
        {
            return attributeData.AttributeClass.ToString() == "System.Web.Mvc.ValidateAntiForgeryTokenAttribute";
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

            bool hasActionMethod = symbol.HasDerivedMethodAttribute(attributeData => MethodsHttp.Contains(attributeData.AttributeClass.ToString()));
            if (!hasActionMethod)
                return;

            bool classHasValidateAntiForgeryToken = symbol.ReceiverType.HasDerivedClassAttribute(HasAntiForgeryToken);
            if (classHasValidateAntiForgeryToken)
                return;

            bool hasValidateAntiForgeryToken = symbol.HasDerivedMethodAttribute(HasAntiForgeryToken);
            if (hasValidateAntiForgeryToken)
                return;

            ctx.ReportDiagnostic(Diagnostic.Create(Rule, node.GetLocation()));
        }
    }
}
