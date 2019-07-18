using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [SecurityAnalyzer(LanguageNames.CSharp)]
    internal class XssPreventionAnalyzerCSharp : XssPreventionAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, CSharp.SyntaxKind.ClassDeclaration);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is CSharpSyntax.ClassDeclarationSyntax node))
                return;

            var classSymbol = CSharp.CSharpExtensions.GetDeclaredSymbol(ctx.SemanticModel, node);
            if (classSymbol == null ||
                !classSymbol.IsDerivedFrom(ControllerNames))
            {
                return;
            }

            var methodsWithParameters = node.DescendantNodesAndSelf()
                                            .OfType<CSharpSyntax.MethodDeclarationSyntax>()
                                            .Where(method => method.ParameterList.Parameters.Any())
                                            .Where(method => method.Modifiers
                                                                   .Any(x => x.IsKind(CSharp.SyntaxKind.PublicKeyword)))
                                            .Where(method => ctx.SemanticModel
                                                                .GetSymbolInfo(method.ReturnType)
                                                                .Symbol
                                                                ?.IsType("System.String") == true);

            foreach (CSharpSyntax.MethodDeclarationSyntax method in methodsWithParameters)
            {
                DataFlowAnalysis flow;
                
                if (method.Body?.Statements != null)
                {
                    var methodStatements = method.Body.Statements;
                    if (!methodStatements.Any())
                        continue;

                    flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(), methodStatements.Last());
                }
                else if (method.ExpressionBody != null)
                {
                    var expression = method.ExpressionBody.Expression;
                    flow = ctx.SemanticModel.AnalyzeDataFlow(expression);
                }
                else
                {
                    continue;
                }

                var methodInvocations =
                    method
                        .DescendantNodes()
                        .OfType<CSharpSyntax.InvocationExpressionSyntax>()
                        .ToArray();

                // Returns from the Data Flow Analysis of input data 
                // Dangerous data is: Data passed as a parameter that is also returned as is by the method
                var inputVariables = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                         .Union(flow.WrittenInside)
                                                         .Intersect(flow.WrittenOutside)
                                                         .ToArray();

                if (!inputVariables.Any())
                    continue;

                foreach (ISymbol inputVariable in inputVariables)
                {
                    bool inputVariableIsEncoded = false;
                    foreach (CSharpSyntax.InvocationExpressionSyntax methodInvocation in methodInvocations)
                    {
                        var arguments = methodInvocation.ArgumentList.Arguments;
                        if (!arguments.Any())
                            continue;

                        if (arguments.First().ToString().Contains(inputVariable.Name))
                        {
                            inputVariableIsEncoded = true;
                        }
                    }

                    if (!inputVariableIsEncoded)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, inputVariable.Locations[0]));
                        break;
                    }
                }
            }
        }
    }

    [SecurityAnalyzer(LanguageNames.VisualBasic)]
    internal class XssPreventionAnalyzerVisualBasic : XssPreventionAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, VB.SyntaxKind.ClassBlock);
        }

        protected void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is VBSyntax.ClassBlockSyntax node))
                return;

            var classSymbol = VB.VisualBasicExtensions.GetDeclaredSymbol(ctx.SemanticModel, node);
            if (classSymbol == null ||
                !classSymbol.IsDerivedFrom(ControllerNames))
            {
                return;
            }

            var methodsWithParameters = node.DescendantNodesAndSelf()
                                            .OfType<VBSyntax.MethodBlockSyntax>()
                                            .Where(method =>
                                                       method.SubOrFunctionStatement.ParameterList.Parameters.Any())
                                            .Where(method => method
                                                             .SubOrFunctionStatement
                                                             .Modifiers.Any(x => x.IsKind(VB.SyntaxKind.PublicKeyword)))
                                            .Where(method =>
                                            {
                                                var retType = method.SubOrFunctionStatement.AsClause?.Type;
                                                if (retType == null)
                                                    return false;

                                                return ctx.SemanticModel
                                                          .GetSymbolInfo(retType)
                                                          .Symbol
                                                          ?.IsType("System.String") == true;
                                            });

            foreach (VBSyntax.MethodBlockSyntax method in methodsWithParameters)
            {
                SyntaxList<VBSyntax.StatementSyntax> methodStatements = method.Statements;
                var methodInvocations = method.DescendantNodes()
                                              .OfType<VBSyntax.InvocationExpressionSyntax>()
                                              .ToArray();

                if (!methodStatements.Any())
                    continue;

                DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(),
                                                                          methodStatements.Last());

                // Returns from the Data Flow Analysis of input data 
                // Dangerous data is: Data passed as a parameter that is also returned as is by the method
                var inputVariables = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                        .Union(flow.WrittenInside)
                                                        .Intersect(flow.WrittenOutside)
                                                        .ToArray();

                if (!inputVariables.Any())
                    continue;

                foreach (ISymbol inputVariable in inputVariables)
                {
                    bool inputVariableIsEncoded = false;
                    foreach (VBSyntax.InvocationExpressionSyntax methodInvocation in methodInvocations)
                    {
                        var arguments = methodInvocation.ArgumentList.Arguments;
                        if (!arguments.Any())
                            continue;

                        if (arguments.First().ToString().Contains(inputVariable.Name))
                        {
                            inputVariableIsEncoded = true;
                        }
                    }

                    if (!inputVariableIsEncoded)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, inputVariable.Locations[0]));
                        break;
                    }
                }
            }
        }
    }

    // TODO: make this generic. 
    // Problem #1: So many language specific syntax nodes.
    // Problem #2: Literal strings are different.

    internal abstract class XssPreventionAnalyzer : SecurityAnalyzer
    {
        public const string DiagnosticId = "SCS0029";

        private List<string> EncodingMethods = new List<string>
        {
            "HtmlEncoder.Default.Encode",
            "HttpContext.Server.HtmlEncode"
        };

        protected string[] ControllerNames = { "Microsoft.AspNetCore.Mvc.Controller", "System.Web.Mvc.Controller" };

        protected static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);
    }
}
