using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using RoslynSecurityGuard.Analyzers.Locale;

using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class RequestValidationAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0017");
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);
        
        public override void Initialize(AnalysisContext context)
        {
            // Seperated the parsers on this one as they use too many language dependant syntax types. 
            // TODO: Review to see if this can be simplified. 
            context.RegisterSyntaxNodeAction(VisitMethodsCSharp, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic, VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic, VB.SyntaxKind.SubBlock);
        }

        private void VisitMethodsCSharp(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as CSharpSyntax.MethodDeclarationSyntax;

            if (node == null) return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.AttributeLists)
            {
                if (attribute.Attributes.Count == 0) continue; //Bound check .. Unlikely to happens

                var att = attribute.Attributes[0];
                //Extract the annotation identifier
                var identifier = att.Name as CSharpSyntax.IdentifierNameSyntax;

                if(identifier == null) continue;

                if (identifier.Identifier.Text == "ValidateInput")
                {
                    var hasArgumentFalse = false;
                    CSharpSyntax.ExpressionSyntax expression = null;
                    foreach (var arg in att.ArgumentList.Arguments) {
                        var literal = arg.Expression as CSharpSyntax.LiteralExpressionSyntax;
                        if (literal.Token.ValueText == "false") {
                            hasArgumentFalse = true;
                            expression = arg.Expression;
                        }
                    }

                    if(hasArgumentFalse && expression != null)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                    }
                }
            }                
        }

        private void VisitMethodsVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as VBSyntax.MethodBlockSyntax;

            if (node == null) return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.BlockStatement.AttributeLists)
            {
                if (attribute.Attributes.Count == 0) continue; //Bound check .. Unlikely to happens

                var att = attribute.Attributes[0];
                //Extract the annotation identifier
                var identifier = att.Name as VBSyntax.IdentifierNameSyntax;

                if (identifier == null) continue;

                if (identifier.Identifier.Text == "ValidateInput")
                {
                    var hasArgumentFalse = false;
                    VBSyntax.ExpressionSyntax expression = null;
                    foreach (var arg in att.ArgumentList.Arguments)
                    {
                        var literal = arg.GetExpression() as VBSyntax.LiteralExpressionSyntax;
                        if (literal.Token.ValueText == "False")
                        {
                            hasArgumentFalse = true;
                            expression = arg.GetExpression();
                        }
                    }

                    if (hasArgumentFalse && expression != null)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                    }
                }
            }
        }
    }
}
