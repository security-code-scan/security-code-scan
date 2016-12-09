using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class TaintAnalyzer : DiagnosticAnalyzer
    {
        private readonly List<DiagnosticDescriptor> Descriptors = new List<DiagnosticDescriptor>();
        
        private MethodBehaviorRepository behaviorRepo = new MethodBehaviorRepository();

        private static List<TaintAnalyzerExtension> extensions = new List<TaintAnalyzerExtension>();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                HashSet<DiagnosticDescriptor> all = new HashSet<DiagnosticDescriptor>(Descriptors);
                //Add the diagnostic that can be reported by taint analysis extension
                foreach (var extension in extensions)
                {
                    var analyzer = extension as DiagnosticAnalyzer;
                    foreach (DiagnosticDescriptor desc in analyzer.SupportedDiagnostics)
                    {
                        all.Add(desc);
                    }
                }
                return ImmutableArray.Create(all.ToArray());
            }
        }

        public TaintAnalyzer()
        {
            //Load injectable APIs
            behaviorRepo.LoadConfiguration("Sinks.yml");
            //Load password APIs
            behaviorRepo.LoadConfiguration("Passwords.yml");

            //Build the descriptor based on the locale fields of the Sinks.yml
            //This must be done in the constructor because, the array need be available before SupportedDiagnostics is first invoked.
            foreach (var desc in behaviorRepo.GetDescriptors())
            {
                Descriptors.Add(desc);
            }
        }
        
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        public static void RegisterExtension(TaintAnalyzerExtension extension) {
            extensions.Add(extension);
        }


        #region Symbolic execution of the code (Visit Method)

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;
            try
            {

                if (node != null)
                {
                    var state = new ExecutionState(ctx);

                    foreach (var ext in extensions)
                    {
                        ext.VisitBeginMethodDeclaration(node, state);
                    }

                    VisitMethodDeclaration(node, state);

                    foreach (var ext in extensions)
                    {
                        ext.VisitEndMethodDeclaration(node, state);
                    }
                }
            }
            catch (Exception e) {
                //Intercept the exception for logging. Otherwise, the analyzer will failed silently.
                string methodName = node.Identifier.Text;
                SGLogging.Log(string.Format("Unhandle exception while visiting method {0} : {1}", methodName, e.Message));
                throw e;
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

            if (node.Body != null) {
                foreach (StatementSyntax statement in node.Body.Statements) {
                    VisitNode(statement, state);

                    foreach (var ext in extensions)
                    {
                        ext.VisitStatement(statement, state);
                    }
                }
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
        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            //SGLogging.Log(node.GetType().ToString());
            
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

            else
            {
                foreach (var n in node.ChildNodes())
                {
                    VisitNode(n, state);
                }
            }

            var isBlockStatement = node is BlockSyntax || node is IfStatementSyntax || node is ForEachStatementSyntax || node is ForStatementSyntax;

            if(!isBlockStatement)
            {
                SGLogging.Log("Unsupported statement " + node.GetType() + " (" + node.ToString() + ")");
            }

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

            else if (expression is AssignmentExpressionSyntax)
            {
                var assignment = (AssignmentExpressionSyntax)expression;
                return VisitAssignment(assignment, state);
            }
            else if (expression is MemberAccessExpressionSyntax)
            {
                var memberAccess = (MemberAccessExpressionSyntax)expression;
                var leftExpression = memberAccess.Expression;
                var name = memberAccess.Name;
                return VisitExpression(leftExpression, state);
            }
            else if (expression is ElementAccessExpressionSyntax)
            {
                var elementAccess = (ElementAccessExpressionSyntax)expression;
                return VisitElementAccess(elementAccess, elementAccess.ArgumentList, state);
            }
            else if (expression is ArrayCreationExpressionSyntax)
            {
                var arrayCreation = (ArrayCreationExpressionSyntax)expression;
                return VisitArrayCreation(arrayCreation, state);
            }
            else if (expression is TypeOfExpressionSyntax)
            {
                var typeofEx = (TypeOfExpressionSyntax)expression;
                return new VariableState(VariableTaint.SAFE);
            }
            else if (expression is ConditionalExpressionSyntax)
            {
                var conditional = (ConditionalExpressionSyntax)expression;
                VisitExpression(conditional.Condition, state);
                var finalState = new VariableState(VariableTaint.SAFE);

                var whenTrueState = VisitExpression(conditional.WhenTrue, state);
                finalState.merge(whenTrueState);
                var whenFalseState = VisitExpression(conditional.WhenFalse, state);
                finalState.merge(whenFalseState);

                return finalState;
            }
            else if (expression is CheckedExpressionSyntax)
            {
                var checkedEx = (CheckedExpressionSyntax)expression;
                return VisitExpression(checkedEx.Expression, state);
            }
            else if (expression is QueryExpressionSyntax)
            {
                var query = (QueryExpressionSyntax)expression;
                var body = query.Body;
                new VariableState(VariableTaint.UNKNOWN);
            }

            SGLogging.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");

            //Unsupported expression
            return new VariableState(VariableTaint.UNKNOWN);
        }

        private VariableState VisitElementAccess(ElementAccessExpressionSyntax elementAccess, BracketedArgumentListSyntax argumentList, ExecutionState state)
        {
            foreach (var argument in argumentList.Arguments)
            {
                VisitExpression(argument.Expression, state);
            }
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

        private VariableState VisitArrayCreation(ArrayCreationExpressionSyntax node, ExecutionState state) {
            var arrayInit = node.Initializer;

            var finalState = new VariableState(VariableTaint.SAFE);
            foreach (var ex in arrayInit.Expressions)
            {
                var exprState = VisitExpression(ex, state);
                finalState = finalState.merge(exprState);
            }
            return finalState;
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
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            int i = 0;
            if (argList == null) {
                return new VariableState(VariableTaint.UNKNOWN);
            }
            foreach (var argument in argList.Arguments)
            {
                var argumentState = VisitExpression(argument.Expression, state);

                if(symbol != null)
                {
                    SGLogging.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
                }

                if (behavior != null && //If the API is at risk
                    (argumentState.taint == VariableTaint.TAINTED || //Tainted values
                    argumentState.taint == VariableTaint.UNKNOWN) &&
                    Array.Exists(behavior.injectablesArguments, element => element == i) //If the current parameter can be injected.
                    )
                {
                    var newRule = LocaleUtil.GetDescriptor(behavior.localeInjection);
                    var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                    state.AnalysisContext.ReportDiagnostic(diagnostic);
                }
                else if (behavior != null &&
                    argumentState.taint == VariableTaint.CONSTANT && //Hard coded value
                    Array.Exists(behavior.passwordArguments, element => element == i) //If the current parameter is a password
                    ) {

                    var newRule = LocaleUtil.GetDescriptor(behavior.localePassword);
                    var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                    state.AnalysisContext.ReportDiagnostic(diagnostic);
                }

                //TODO: tainted all object passed in argument

                i++;
            }

            //Additionnal analysis by extension
            foreach (var ext in extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            return new VariableState(VariableTaint.UNKNOWN);
        }

        private VariableState VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state)
        {
            
            var symbol = state.GetSymbol(node.Left);
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            var variableState = VisitExpression(node.Right, state);

           if(node.Left is IdentifierNameSyntax)
            {
                var assignmentIdentifier = node.Left as IdentifierNameSyntax;
                state.MergeValue(ResolveIdentifier(assignmentIdentifier.Identifier), variableState);
            }

            if (behavior != null && //Injection
                    behavior.isInjectableField &&
                    variableState.taint != VariableTaint.CONSTANT && //Skip safe values
                    variableState.taint != VariableTaint.SAFE)
            {
                var newRule = LocaleUtil.GetDescriptor(behavior.localeInjection);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
            if (behavior != null && //Known Password API
                    behavior.isPasswordField &&
                    variableState.taint == VariableTaint.CONSTANT //Only constant
                    )
            {
                var newRule = LocaleUtil.GetDescriptor(behavior.localePassword);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
            

            //TODO: tainted the variable being assign.

            //Additionnal analysis by extension
            foreach (var ext in extensions)
            {
                ext.VisitAssignment(node, state, behavior, symbol, variableState);
            }

            return variableState;
        }


        /// <summary>
        /// Identifier name include variable name.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            var value = ResolveIdentifier(expression.Identifier);
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


        #endregion
    }
}
