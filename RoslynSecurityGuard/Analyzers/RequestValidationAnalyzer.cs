using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
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
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;

            if (node == null)
            { //Not the expected node type
                return;
            }

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.AttributeLists)
            {
                if (attribute.Attributes.Count == 0) continue; //Bound check .. Unlikely to happens

                var att = attribute.Attributes[0];
                //Extract the annotation identifier
                var identifier = att.Name as IdentifierNameSyntax;

                if(identifier == null) continue;

                if (identifier.Identifier.Text == "ValidateInput")
                {
                    var hasArgumentFalse = false;
                    ExpressionSyntax expression = null;
                    foreach (var arg in att.ArgumentList.Arguments) {
                        var literal = arg.Expression as LiteralExpressionSyntax;
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
    }
}
