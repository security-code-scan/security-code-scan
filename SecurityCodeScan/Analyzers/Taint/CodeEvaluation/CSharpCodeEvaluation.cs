using System;
using System.Collections.Generic;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Symbolic execution of C# code
    /// </summary>
    public class CSharpCodeEvaluation : BaseCodeEvaluation
    {
        public static List<TaintAnalyzerExtension> Extensions { get; set; } = new List<TaintAnalyzerExtension>();

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;
            try
            {
                if (node == null)
                    return;

                var state = new ExecutionState(ctx);

                foreach (var ext in Extensions)
                {
                    ext.VisitBeginMethodDeclaration(node, state);
                }

                VisitMethodDeclaration(node, state);

                foreach (var ext in Extensions)
                {
                    ext.VisitEndMethodDeclaration(node, state);
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer will failed silently.
                string methodName = node != null ? node.Identifier.Text : string.Empty;
                string errorMsg   = $"Unhandled exception while visiting method {methodName} : {e.Message}";
                Logger.Log(errorMsg);
                Logger.Log(e.StackTrace, false);
                throw new Exception(errorMsg, e);
            }
        }

        private VariableState VisitBlock(BlockSyntax node, ExecutionState state)
        {
            var lastState = new VariableState(node, VariableTaint.Unknown);

            foreach (StatementSyntax statement in node.Statements)
            {
                var statementState = VisitNode(statement, state);
                lastState = statementState;

                foreach (var ext in Extensions)
                {
                    ext.VisitStatement(statement, state);
                }
            }

            return lastState;
        }

        /// <summary>
        /// Entry point that visit the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in node.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier),
                                  new VariableState(parameter, VariableTaint.Tainted));
            }

            if (node.Body == null)
                return new VariableState(node, VariableTaint.Unknown);

            return VisitBlock(node.Body, state);
        }

        private VariableState VisitForEach(ForEachStatementSyntax node, ExecutionState state)
        {
            state.AddNewValue(ResolveIdentifier(node.Identifier), VisitExpression(node.Expression, state));
            return VisitNode(node.Statement, state);
        }

        /// <summary>
        /// Statement are all segment separate by semi-colon.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            //Logger.Log(node.GetType().ToString());

            switch (node)
            {
                case LocalDeclarationStatementSyntax declarationStatementSyntax:
                    return VisitLocalDeclaration(declarationStatementSyntax, state);
                case VariableDeclarationSyntax variableDeclarationSyntax:
                    return VisitVariableDeclaration(variableDeclarationSyntax, state);
                case ExpressionStatementSyntax expressionStatementSyntax:
                    return VisitExpressionStatement(expressionStatementSyntax, state);
                case ExpressionSyntax expressionSyntax:
                    return VisitExpression(expressionSyntax, state);
                case MethodDeclarationSyntax methodDeclarationSyntax:
                    return VisitMethodDeclaration(methodDeclarationSyntax, state);
                case ReturnStatementSyntax returnStatementSyntax:
                    if (returnStatementSyntax.Expression == null)
                        return new VariableState(node, VariableTaint.Unknown);

                    return VisitExpression(returnStatementSyntax.Expression, state);
                case ForEachStatementSyntax forEachSyntax:
                    return VisitForEach(forEachSyntax, state);
                case BlockSyntax blockSyntax:
                    return VisitBlock(blockSyntax, state);
            }

            foreach (var n in node.ChildNodes())
            {
                VisitNode(n, state);
            }

            var isBlockStatement = node is IfStatementSyntax ||
                                   node is ForStatementSyntax;

            if (!isBlockStatement)
            {
                Logger.Log("Unsupported statement " + node.GetType() + " (" + node.ToString() + ")");
            }

            return new VariableState(node, VariableTaint.Unknown);
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
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclarationSyntax declaration, ExecutionState state)
        {
            var lastState = new VariableState(declaration, VariableTaint.Unknown);

            foreach (var variable in declaration.Variables)
            {
                var identifier  = variable.Identifier;
                var initializer = variable.Initializer;
                if (initializer == null)
                    continue;

                EqualsValueClauseSyntax equalsClause = initializer;

                VariableState varState = VisitExpression(equalsClause.Value, state);
                //varState.SetType(lastState.type);
                state.AddNewValue(ResolveIdentifier(identifier), varState);
                lastState = varState;
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
            switch (expression)
            {
                case InvocationExpressionSyntax invocationExpressionSyntax:
                    return VisitMethodInvocation(invocationExpressionSyntax, state);
                case ObjectCreationExpressionSyntax objectCreationExpressionSyntax:
                    return VisitObjectCreation(objectCreationExpressionSyntax, state);
                case LiteralExpressionSyntax _:
                    return new VariableState(expression, VariableTaint.Constant);
                case IdentifierNameSyntax identifierNameSyntax:
                    return VisitIdentifierName(identifierNameSyntax, state);
                case BinaryExpressionSyntax binaryExpressionSyntax:
                    return VisitBinaryExpression(binaryExpressionSyntax, state);
                case AssignmentExpressionSyntax assignmentExpressionSyntax:
                    return VisitAssignment(assignmentExpressionSyntax, state);
                case MemberAccessExpressionSyntax memberAccessExpressionSyntax:
                    return VisitExpression(memberAccessExpressionSyntax.Name, state);
                case ElementAccessExpressionSyntax elementAccessExpressionSyntax:
                    return VisitElementAccess(elementAccessExpressionSyntax, elementAccessExpressionSyntax.ArgumentList, state);
                case ArrayCreationExpressionSyntax arrayCreationExpressionSyntax:
                    return VisitArrayCreation(arrayCreationExpressionSyntax, arrayCreationExpressionSyntax.Initializer, state);
                case ImplicitArrayCreationExpressionSyntax implicitArrayCreationExpressionSyntax:
                    return VisitArrayCreation(implicitArrayCreationExpressionSyntax, implicitArrayCreationExpressionSyntax.Initializer, state);
                case TypeOfExpressionSyntax typeOfExpressionSyntax:
                    return new VariableState(typeOfExpressionSyntax, VariableTaint.Safe);
                case ConditionalExpressionSyntax conditionalExpressionSyntax:
                    VisitExpression(conditionalExpressionSyntax.Condition, state);
                    var finalState = new VariableState(conditionalExpressionSyntax, VariableTaint.Safe);

                    var whenTrueState  = VisitExpression(conditionalExpressionSyntax.WhenTrue, state);
                    finalState         = finalState.Merge(whenTrueState);
                    var whenFalseState = VisitExpression(conditionalExpressionSyntax.WhenFalse, state);
                    finalState         = finalState.Merge(whenFalseState);

                    return finalState;
                case CheckedExpressionSyntax checkedExpressionSyntax:
                    return VisitExpression(checkedExpressionSyntax.Expression, state);
                case QueryExpressionSyntax queryExpressionSyntax:
                    return new VariableState(queryExpressionSyntax, VariableTaint.Unknown);
                case InterpolatedStringExpressionSyntax interpolatedStringExpressionSyntax:
                    return VisitInterpolatedString(interpolatedStringExpressionSyntax, state);
            }

            Logger.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");
            return new VariableState(expression, VariableTaint.Unknown);
        }

        private VariableState VisitInterpolatedString(InterpolatedStringExpressionSyntax interpolatedString,
                                                      ExecutionState                     state)
        {
            var varState = new VariableState(interpolatedString, VariableTaint.Constant);

            foreach (var content in interpolatedString.Contents)
            {
                if (content is InterpolatedStringTextSyntax textString)
                {
                    varState = varState.Merge(new VariableState(textString, VariableTaint.Constant));
                }

                if (!(content is InterpolationSyntax interpolation))
                    continue;

                var expressionState = VisitExpression(interpolation.Expression, state);
                varState            = varState.Merge(expressionState);
            }

            return varState;
        }

        private VariableState VisitElementAccess(ElementAccessExpressionSyntax elementAccess,
                                                 BracketedArgumentListSyntax   argumentList,
                                                 ExecutionState                state)
        {
            foreach (var argument in argumentList.Arguments)
            {
                VisitExpression(argument.Expression, state);
            }

            return new VariableState(elementAccess, VariableTaint.Unknown);
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
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);

            foreach (SyntaxNode child in node.DescendantNodes())
            {
                if (child is AssignmentExpressionSyntax assignmentExpressionSyntax)
                {
                    finalState = finalState.Merge(VisitAssignment(assignmentExpressionSyntax, state));
                }
                else
                {
                    Logger.Log(child.GetText().ToString().Trim() + " -> " + finalState);
                }
            }

            return finalState;
        }

        private VariableState VisitArrayCreation(SyntaxNode node, InitializerExpressionSyntax arrayInit, ExecutionState state)
        {
            var finalState = new VariableState(node, VariableTaint.Safe);
            if (arrayInit == null)
                return finalState;

            foreach (var ex in arrayInit.Expressions)
            {
                var exprState = VisitExpression(ex, state);
                finalState    = finalState.Merge(exprState);
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
        private VariableState VisitInvocationAndCreation(ExpressionSyntax   node,
                                                         ArgumentListSyntax argList,
                                                         ExecutionState     state)
        {
            if (argList == null)
            {
                return new VariableState(node, VariableTaint.Unknown);
            }

            var symbol      = state.GetSymbol(node);
            var behavior    = BehaviorRepo.GetMethodBehavior(symbol);
            var returnState = new VariableState(node, VariableTaint.Safe);

            for (var i = 0; i < argList.Arguments.Count; i++)
            {
                var argument      = argList.Arguments[i];
                var argumentState = VisitExpression(argument.Expression, state);

                if (symbol != null)
                {
                    Logger.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
                }

                if (behavior != null)
                {
                    //If the API is at risk
                    if ((argumentState.Taint == VariableTaint.Tainted ||
                         argumentState.Taint == VariableTaint.Unknown) && //Tainted values
                        //If the current parameter can be injected.
                        Array.Exists(behavior.InjectablesArguments, element => element == i))
                    {
                        var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                    else if (argumentState.Taint == VariableTaint.Constant && //Hard coded value
                             //If the current parameter is a password
                             Array.Exists(behavior.PasswordArguments, element => element == i))
                    {
                        var newRule    = LocaleUtil.GetDescriptor(behavior.LocalePassword);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                    else if (Array.Exists(behavior.TaintFromArguments, element => element == i))
                    {
                        returnState = returnState.Merge(argumentState);
                    }
                }

                //TODO: tainted all object passed in argument
            }

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            var hasTaintFromArguments = behavior?.TaintFromArguments?.Length > 0;
            return hasTaintFromArguments ? returnState : new VariableState(node, VariableTaint.Unknown);
        }

        private VariableState VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state)
        {
            var            symbol   = state.GetSymbol(node.Left);
            MethodBehavior behavior = BehaviorRepo.GetMethodBehavior(symbol);

            var variableState = VisitExpression(node.Right, state);

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitAssignment(node, state, behavior, symbol, variableState);
            }

            IdentifierNameSyntax parentIdentifierSyntax = GetParentIdentifier(node.Left);
            if (parentIdentifierSyntax != null)
            {
                state.MergeValue(ResolveIdentifier(parentIdentifierSyntax.Identifier), variableState);
            }

            if (behavior != null                              && //Injection
                behavior.IsInjectableField                    &&
                variableState.Taint != VariableTaint.Constant && //Skip safe values
                variableState.Taint != VariableTaint.Safe)
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocaleInjection);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            if (behavior != null         && //Known Password API
                behavior.IsPasswordField &&
                variableState.Taint == VariableTaint.Constant) //Only constant
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.LocalePassword);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            //TODO: tainted the variable being assign.

            return variableState;
        }

        /// <summary>
        /// Return the top member from an assignment.
        /// <code>
        /// a.b.c = 1234; //Will return a
        /// d.e = 1234 //Will return d
        /// </code>
        /// </summary>
        /// <param name="expression"></param>
        /// <returns></returns>
        private IdentifierNameSyntax GetParentIdentifier(ExpressionSyntax expression)
        {
            while (true)
            {
                if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
                    break;

                expression = memberAccessExpressionSyntax.Expression;
            }

            var identifierNameSyntax = expression as IdentifierNameSyntax;
            return identifierNameSyntax;
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
            if (state.VariableStates.TryGetValue(value, out var varState))
                return varState;

            // Recursion prevention: set the value into the map if we'll get back resolving it while resolving it dependency
            state.AddNewValue(value, new VariableState(expression, VariableTaint.Unknown));

            var symbol = state.GetSymbol(expression);
            if (symbol == null)
                return new VariableState(expression, VariableTaint.Unknown);

            if (symbol is IFieldSymbol field)
            {
                if (field.IsConst)
                    return new VariableState(expression, VariableTaint.Constant);

                if (!field.IsReadOnly)
                    return new VariableState(expression, VariableTaint.Unknown);

                if (field.IsType("System.String.Empty"))
                    return new VariableState(expression, VariableTaint.Constant);

                return new VariableState(expression, VariableTaint.Unknown);
            }

            if (symbol is IPropertySymbol prop)
            {
                if (prop.IsVirtual || prop.IsOverride || prop.IsAbstract)
                    return new VariableState(expression, VariableTaint.Unknown);

                // TODO: Use public API
                var syntaxNodeProperty = prop.GetMethod.GetType().GetTypeInfo().BaseType.GetTypeInfo().GetDeclaredProperty("BodySyntax");
                if (syntaxNodeProperty == null)
                    return new VariableState(expression, VariableTaint.Unknown);

                var syntaxNode = (CSharpSyntaxNode)syntaxNodeProperty.GetValue(prop.GetMethod);
                if (syntaxNode is BlockSyntax blockSyntax)
                    return VisitBlock(blockSyntax, state);

                if (syntaxNode is ArrowExpressionClauseSyntax arrowSyntax)
                    return VisitExpression(arrowSyntax.Expression, state);

                return new VariableState(expression, VariableTaint.Unknown);
            }

            return new VariableState(expression, VariableTaint.Unknown);
        }

        /// <summary>
        /// Combine the state of the two operands. Binary expression include concatenation.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitBinaryExpression(BinaryExpressionSyntax expression, ExecutionState state)
        {
            VariableState left  = VisitExpression(expression.Left,  state);
            VariableState right = VisitExpression(expression.Right, state);
            return left.Merge(right);
        }
    }
}
