using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class RequestValidationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0017");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            // Separated the parsers on this one as they use too many language dependent syntax types. 
            // TODO: Review to see if this can be simplified. 
            context.RegisterSyntaxNodeAction(VisitMethodsCSharp,      CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic, VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic, VB.SyntaxKind.SubBlock);
        }

        private void VisitMethodsCSharp(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is CSharpSyntax.MethodDeclarationSyntax node))
                return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.AttributeLists)
            {
                if (attribute.Attributes.Count == 0)
                    continue; //Bound check .. Unlikely to happen

                var att = attribute.Attributes[0];

                //Extract the annotation identifier
                if (!(att.Name is CSharpSyntax.IdentifierNameSyntax identifier))
                    continue;

                if (identifier.Identifier.Text != "ValidateInput")
                    continue;

                var                           hasArgumentFalse = false;
                CSharpSyntax.ExpressionSyntax expression       = null;
                foreach (var arg in att.ArgumentList.Arguments)
                {
                    var literal = (CSharpSyntax.LiteralExpressionSyntax)arg.Expression;
                    if (literal.Token.ValueText != "false")
                        continue;

                    hasArgumentFalse = true;
                    expression       = arg.Expression;
                }

                if (hasArgumentFalse && expression != null)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                }
            }
        }

        private void VisitMethodsVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is VBSyntax.MethodBlockSyntax node))
                return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.BlockStatement.AttributeLists)
            {
                if (attribute.Attributes.Count == 0)
                    continue; //Bound check .. Unlikely to happen

                var att = attribute.Attributes[0];

                //Extract the annotation identifier
                if (!(att.Name is VBSyntax.IdentifierNameSyntax identifier))
                    continue;

                if (identifier.Identifier.Text != "ValidateInput")
                    continue;

                var                       hasArgumentFalse = false;
                VBSyntax.ExpressionSyntax expression       = null;
                foreach (var arg in att.ArgumentList.Arguments)
                {
                    var literal = (VBSyntax.LiteralExpressionSyntax)arg.GetExpression();
                    if (literal.Token.ValueText != "False")
                        continue;

                    hasArgumentFalse = true;
                    expression       = arg.GetExpression();
                }

                if (hasArgumentFalse && expression != null)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                }
            }
        }
    }
}
