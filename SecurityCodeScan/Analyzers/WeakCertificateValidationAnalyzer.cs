#nullable disable
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using System.Collections.Immutable;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using System.Diagnostics;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCertificateValidationAnalyzerCSharp : WeakCertificateValidationAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            InitConfig(context);
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, CSharpSyntaxNodeHelper.Default),
                                             CSharp.SyntaxKind.SimpleAssignmentExpression, CSharp.SyntaxKind.AddAssignmentExpression);
        }

        protected override SyntaxNode GetBody(SyntaxNode rightNode, SyntaxNodeAnalysisContext ctx)
        {
            if (rightNode == null)
                return null;

            CSharp.CSharpSyntaxNode body;
            switch (rightNode)
            {
                case CSharp.Syntax.ParenthesizedLambdaExpressionSyntax lambda:
                    body = lambda.Body;
                    break;
                case CSharp.Syntax.AnonymousMethodExpressionSyntax anonymous:
                    body = anonymous.Body;
                    break;
                default:
                    return null;
            }

            // Roslyn fails to get constant of something as "return true;"
            // get the simplest case
            // todo: use taint analyzer to get the value?

            if (body is CSharp.Syntax.BlockSyntax block &&
                block.Statements.Count == 1)
            {
                var statement = block.Statements.First();
                if (statement is CSharp.Syntax.ReturnStatementSyntax ret)
                {
                    return ret.Expression;
                }
            }

            return body;
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakCertificateValidationAnalyzerVisualBasic : WeakCertificateValidationAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            InitConfig(context);
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, VBSyntaxNodeHelper.Default),
                                             VB.SyntaxKind.SimpleAssignmentStatement, VB.SyntaxKind.AddAssignmentStatement);
        }

        protected override SyntaxNode GetBody(SyntaxNode rightNode, SyntaxNodeAnalysisContext ctx)
        {
            if (rightNode == null)
                return null;

            VB.VisualBasicSyntaxNode body;
            switch (rightNode)
            {
                case VB.Syntax.SingleLineLambdaExpressionSyntax lambda:
                    body = lambda.Body;
                    break;
                case VB.Syntax.MultiLineLambdaExpressionSyntax lambda:
                    body = lambda;
                    break;
                default:
                    return null;
            }

            if (body is VB.Syntax.MultiLineLambdaExpressionSyntax block &&
                block.Statements.Count == 1)
            {
                var statement = block.Statements.First();
                if (statement is VB.Syntax.ReturnStatementSyntax ret)
                {
                    return ret.Expression;
                }
            }

            return body;
        }
    }

    public abstract class WeakCertificateValidationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0004");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        protected abstract SyntaxNode GetBody(SyntaxNode rightNode, SyntaxNodeAnalysisContext ctx);


        private Configuration Config;

        protected void InitConfig(CompilationStartAnalysisContext context)
        {
            Config = Configuration.GetOrCreate(context);
        }

        protected void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var leftNode = nodeHelper.GetAssignmentLeftNode(ctx.Node);
            var symbol  = ctx.SemanticModel.GetSymbolInfo(leftNode).Symbol;
            if (symbol == null)
                return;

            if (Config.AuditMode &&
                symbol.IsType("System.Net.ServicePointManager.CertificatePolicy"))
            {
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, ctx.Node.GetLocation()));
                return;
            }

            if (!IsMatch(symbol))
                return;

            var rightNode = GetBody(nodeHelper.GetAssignmentRightNode(ctx.Node), ctx);
            if (rightNode == null)
                return;

            var rightValue = ctx.SemanticModel.GetConstantValue(rightNode);

            if (!rightValue.HasValue && Config.AuditMode)
            {
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, ctx.Node.GetLocation()));
                return;
            }

            if (rightValue.Value is bool value && value)
            {
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, ctx.Node.GetLocation()));
                return;
            }

            if (Config.AuditMode)
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, ctx.Node.GetLocation()));
        }

        private static bool IsMatch(ISymbol symbolMemberAccess)
        {
            return symbolMemberAccess.IsType("System.Net.ServicePointManager.ServerCertificateValidationCallback")    ||
                   symbolMemberAccess.IsType("System.Net.Http.WebRequestHandler.ServerCertificateValidationCallback") ||
                   symbolMemberAccess.IsType("System.Net.HttpWebRequest.ServerCertificateValidationCallback") ||
                   symbolMemberAccess.IsType("System.Net.Http.HttpClientHandler.ServerCertificateCustomValidationCallback");
        }
    }
}
