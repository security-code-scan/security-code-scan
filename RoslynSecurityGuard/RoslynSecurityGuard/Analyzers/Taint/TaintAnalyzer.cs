using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Utils;
using System;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class TaintAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0002", typeof(LinqSqlInjectionAnalyzer).Name, DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        MethodBehaviorRepository behaviorRepo = new MethodBehaviorRepository();

        public override void Initialize(AnalysisContext context)
        {
            //Load methods configurations
            behaviorRepo.LoadConfiguration("Sinks.yml");

            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;

            if (node != null)
            {
                VisitMethodDeclaration(node, new ExecutionState(ctx));
            }
        }

        /// <summary>
        /// Entry point that visit the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax statement in node.ParameterList.Parameters) {
                state.AddNewValue(ResolveIdentifier(statement.Identifier), new VariableState(VariableTaint.TAINTED));
            }

            foreach (StatementSyntax statement in node.Body.Statements)
            {
                VisitStatement(statement, state);
            }
            //The state return is irrelevant because it is not use.
            return new VariableState(VariableTaint.UNKNOWN);
        }

        /// <summary>
        /// Statement are all segment separate by semi-colon.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="ctx"></param>
        /// <param name="state"></param>
        private VariableState VisitStatement(SyntaxNode node, ExecutionState state)
        {
            SGLogging.Log(node.GetType().ToString());

            //Variable allocation
            if (node is LocalDeclarationStatementSyntax)
            {
                var declaration = (LocalDeclarationStatementSyntax)node;
                return VisitLocalDeclaration(declaration, state);
            }
            else if (node is VariableDeclarationSyntax)
            {
                var declaration = (VariableDeclarationSyntax)node;
                return VisitVariableDeclaration(declaration, state);
            }

            //Expression
            else if (node is ExpressionStatementSyntax)
            {
                var expression = (ExpressionStatementSyntax)node;
                return VisitExpressionStatement(expression, state);
            }
            else if (node is ExpressionSyntax)
            {
                var expression = (ExpressionSyntax)node;
                return VisitExpression(expression, state);
            }
            else if (node is MethodDeclarationSyntax)
            {
                var methodDeclaration = (MethodDeclarationSyntax)node;
                return VisitMethodDeclaration(methodDeclaration, state);
            }

            SGLogging.Log("Unsupported statement " + node.GetType() + " (" + node.ToString() + ")");

            return new VariableState(VariableTaint.UNKNOWN);
        }

        /// <summary>
        /// Unwrap
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitLocalDeclaration(LocalDeclarationStatementSyntax declaration, ExecutionState state)
        {
            return VisitVariableDeclaration(declaration.Declaration, state);
        }

        /// <summary>
        /// Evaluate expression that contains a list of assignment.
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="ctx"></param>
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclarationSyntax declaration, ExecutionState state)
        {
            var variables = declaration.Variables;

            VariableState lastState = new VariableState(VariableTaint.UNKNOWN);

            foreach (var variable in declaration.Variables)
            {
                var identifier = variable.Identifier;
                var initializer = variable.Initializer;
                if (initializer is EqualsValueClauseSyntax)
                {
                    EqualsValueClauseSyntax equalsClause = initializer;

                    VariableState varState = VisitExpression(equalsClause.Value, state);
                    state.AddNewValue(ResolveIdentifier(identifier), varState);
                    lastState = varState;
                }
            }

            //
            return lastState;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="syntaxToken"></param>
        /// <returns></returns>
        private string ResolveIdentifier(SyntaxToken syntaxToken)
        {
            return syntaxToken.Text;
        }


        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            //Invocation
            if (expression is InvocationExpressionSyntax)
            {
                var invocation = (InvocationExpressionSyntax)expression;
                return VisitMethodInvocation(invocation, state);
            }
            else if (expression is ObjectCreationExpressionSyntax)
            {
                var objCreation = (ObjectCreationExpressionSyntax)expression;
                return VisitObjectCreation(objCreation, state);
            }

            else if (expression is LiteralExpressionSyntax)
            {
                return new VariableState(VariableTaint.CONSTANT);
            }
            else if (expression is IdentifierNameSyntax)
            {
                var identifierName = (IdentifierNameSyntax)expression;
                return VisitIdentifierName(identifierName, state);
            }

            //Arithmetic : Addition
            else if (expression is BinaryExpressionSyntax)
            {
                var binaryExpression = (BinaryExpressionSyntax)expression;
                return VisitBinaryExpression(binaryExpression, state);
            }

            SGLogging.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");

            //Unsupported expression
            return new VariableState(VariableTaint.UNKNOWN);
        }

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
        }

        /// <summary>
        /// Logic for each method invocation (including constructor)
        /// The argument list is required because <code>InvocationExpressionSyntax</code> and 
        /// <code>ObjectCreationExpressionSyntax</code> do not share a common interface.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="argList"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state) {
            
            
            var symbol = state.GetSymbol(node);
            MethodBehavior behavior = behaviorRepo.GetInjectableMethodBehavior(symbol);

            int i = 0;
            foreach (var argument in argList.Arguments)
            {
                var argumentState = VisitExpression(argument.Expression, state);

                SGLogging.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);

                if (behavior != null && //If the API is at risk
                    argumentState.taint != VariableTaint.CONSTANT && //Skip safe values
                    argumentState.taint != VariableTaint.SAFE &&
                    Array.Exists(behavior.injectablesArguments, element => element == i) //If the current parameter can be injected.
                    )
                {
                    var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                    state.analysisContext.ReportDiagnostic(diagnostic);
                }

                //TODO: tainted all object passed in argument

                i++;
            }
            return new VariableState(VariableTaint.UNKNOWN);
        }

        /// <summary>
        /// Identifier name include variable name.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            //SGLogging.Log("Visiting identifier " + expression);
            var value = expression.Identifier.Text;
            return state.GetValueByIdentifier(value);
        }

        /// <summary>
        /// Combine the state of the two operands. Binary expression include concatenation.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitBinaryExpression(BinaryExpressionSyntax expression, ExecutionState state)
        {
            VariableState left = VisitExpression(expression.Left, state);
            VariableState right = VisitExpression(expression.Right, state);
            return left.merge(right);
        }

    }
}
