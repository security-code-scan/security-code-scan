using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Immutable;

using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class CsrfTokenAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0016";
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        //99% of the occurences will be HttpPost.. but here are some additionnal HTTP methods
        //https://msdn.microsoft.com/en-us/library/system.web.mvc.actionmethodselectorattribute(v=vs.118).aspx
        private List<string> MethodsHttp = new List<string>() { "HttpPost", "HttpPut", "HttpDelete", "HttpPatch" };

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethods, VB.SyntaxKind.SubBlock, VB.SyntaxKind.FunctionBlock);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            bool hasActionMethod = false;
            bool hasValidateAntiForgeryToken = false;
            SyntaxNode node = null;
            List<string> attributesList;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node = ctx.Node as CSharpSyntax.MethodDeclarationSyntax;
                if (node == null) return;
                attributesList = AnalyzerUtil.getAttributesForMethod((CSharpSyntax.MethodDeclarationSyntax)node);
            }
            else
            {
                node = ctx.Node as VBSyntax.MethodBlockSyntax;
                if (node == null) return;
                attributesList = AnalyzerUtil.getAttributesForMethod((VBSyntax.MethodBlockSyntax)node);
            }

            //Extract the annotation identifier
            foreach (var attribute in attributesList)
            {
                if (MethodsHttp.Contains(attribute))
                {
                    //Create the diagnostic on the annotation rather than the complete method
                    if (ctx.Node.Language == LanguageNames.CSharp) {
                        var attributes = AnalyzerUtil.getAttributesByName(attribute, node as CSharpSyntax.MethodDeclarationSyntax);
                        if (attributes.Count > 0) node = attributes[0];
                    }
                    else {
                        var attributes = AnalyzerUtil.getAttributesByName(attribute, node as VBSyntax.MethodBlockSyntax);
                        if (attributes.Count > 0) node = attributes[0];
                    }
                    hasActionMethod = true;
                }
                else if (attribute.Equals("ValidateAntiForgeryToken"))
                {
                    hasValidateAntiForgeryToken = true;
                }
            }

            if (hasActionMethod && !hasValidateAntiForgeryToken)
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, node.GetLocation()));
        }
    }
}
